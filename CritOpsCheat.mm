// =============================================================
//  CritOpsCheat.mm
//  Critical Ops iOS Cheat — Non-JB IPA Injection Dylib
//  Platform : iOS 14+  ARM64
//  Inject   : insert_dylib --strip-codesig --inplace
//               @executable_path/Frameworks/CritOpsCheat.dylib
//               Payload/CriticalOps.app/CriticalOps
//  Sign     : esign / ksign after repacking .ipa
//  Build    : bash build.sh
//
//  ┌─ FEATURES ──────────────────────────────────────┐
//  │  😵  Head Hitbox Expansion                      │
//  │  👕  Body Hitbox Expansion                      │
//  │  🍃  No Gravity                                 │
//  │  ☁️   No Smoke                                  │
//  │  👀  No Flash                                   │
//  │  👻  Pass Through Walls                         │
//  │  ⏱️   No Equipment Timeout                     │
//  │  🚁  Fly          (level 1–10)                  │
//  │  🐇  Super Jump   (level 1–10)                  │
//  │  ⌛  Fast Time    (level 1–10)                  │
//  └─────────────────────────────────────────────────┘
//
//  ANTI-BAN built-in:
//    • Value jitter      – randomise every write by ±0.002
//    • Telemetry dodge   – restore server-visible values for
//                          500 ms every ~28 s before stat upload
//    • Safe-mode toggle  – one tap disables all server-visible cheats
// =============================================================

#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#include <mach/mach.h>
#include <mach-o/dyld.h>
#include <sys/mman.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#include <pthread.h>

// ─────────────────────────────────────────────────────────────
//  §1  STATE
// ─────────────────────────────────────────────────────────────

typedef struct {
    // toggles
    BOOL headHitbox;
    BOOL bodyHitbox;
    BOOL noGravity;
    BOOL noSmoke;
    BOOL noFlash;
    BOOL passThroughWalls;
    BOOL noEquipTimeout;
    BOOL safeMode;          // disables all server-visible cheats when ON

    // level cheats (0 = off)
    int  flyLevel;          // 1–10
    int  jumpLevel;         // 1–10
    int  timeLevel;         // 1–10
} CheatState;

typedef struct {
    // discovered addresses (0 = not found)
    uintptr_t headHitbox;
    uintptr_t bodyHitbox;
    uintptr_t gravityY;     // Y component of Physics.gravity
    uintptr_t smoke;        // particle density
    uintptr_t flash;        // flash intensity (two floats: addr, addr+4)
    uintptr_t wallCol;      // wall collision radius
    uintptr_t equipTimeout;
    uintptr_t walkSpeed;    // used for fly
    uintptr_t jumpImpulse;
    uintptr_t timeScale;    // Unity Time.timeScale

    // original values (for restore)
    float headHitboxOrig;
    float bodyHitboxOrig;
    float gravityYOrig;
    float smokeOrig;
    float flashOrig;
    float wallColOrig;
    float equipTimeoutOrig;
    float walkSpeedOrig;
    float jumpImpulseOrig;
    float timeScaleOrig;

    BOOL found;
} AddrCache;

static CheatState  gState  = {};
static AddrCache   gCache  = {};
static pthread_mutex_t gMtx = PTHREAD_MUTEX_INITIALIZER;

// ─────────────────────────────────────────────────────────────
//  §2  MEMORY PRIMITIVES
//  Running inside the target process → direct pointer access.
//  mprotect is needed because Unity maps most heaps as RW,
//  but some physics structs land in RO pages — we flip them.
// ─────────────────────────────────────────────────────────────

static void mem_unlock(uintptr_t addr) {
    // ARM64 page size is 16 KB on Apple Silicon, 4 KB on older
    uintptr_t page  = addr & ~0x3FFFUL;
    size_t    psz   = 0x4000;
    mprotect((void *)page, psz, PROT_READ | PROT_WRITE | PROT_EXEC);
}

static float mem_rf(uintptr_t addr) {
    return *(volatile float *)addr;
}

static void mem_wf(uintptr_t addr, float v) {
    if (!addr) return;
    mem_unlock(addr);
    *(volatile float *)addr = v;
    // flush instruction + data cache lines so Unity's JIT sees the change
    __asm__ volatile("dc cvau, %0\n"
                     "ic ivau, %0\n"
                     "dsb ish\n"
                     "isb\n"
                     :: "r"(addr) : "memory");
}

// ─────────────────────────────────────────────────────────────
//  §3  MEMORY SCANNER
//  Walks every readable-writable non-exec page in the process
//  and looks for IEEE-754 float values within a tolerance band.
// ─────────────────────────────────────────────────────────────

// Scan all RW heap regions for a single float
// Returns the FIRST address whose value is within [target±tol]
static uintptr_t scan_single_float(float target, float tol) {
    mach_port_t       task  = mach_task_self();
    mach_vm_address_t addr  = 0;
    mach_vm_size_t    sz    = 0;
    natural_t         depth = 1;

    while (1) {
        vm_region_submap_info_data_64_t info;
        mach_msg_type_number_t cnt = VM_REGION_SUBMAP_INFO_COUNT_64;
        kern_return_t kr = mach_vm_region_recurse(task, &addr, &sz, &depth,
                           (vm_region_recurse_info_t)&info, &cnt);
        if (kr != KERN_SUCCESS) break;

        BOOL rw = (info.protection & VM_PROT_READ)    &&
                  (info.protection & VM_PROT_WRITE)   &&
                 !(info.protection & VM_PROT_EXECUTE);

        if (rw && sz >= 4 && sz <= 256*1024*1024) {
            uintptr_t end = (uintptr_t)(addr + sz) - 4;
            for (uintptr_t p = (uintptr_t)addr; p <= end; p += 4) {
                float v = *(float *)p;
                if (isfinite(v) && fabsf(v - target) <= tol)
                    return p;
            }
        }
        addr += sz;
    }
    return 0;
}

// Scan for a pair of adjacent floats (both within tolerance)
// Returns the address of the FIRST float (second is at addr+4)
static uintptr_t scan_float_pair(float a, float tolA,
                                  float b, float tolB) {
    mach_port_t       task  = mach_task_self();
    mach_vm_address_t addr  = 0;
    mach_vm_size_t    sz    = 0;
    natural_t         depth = 1;

    while (1) {
        vm_region_submap_info_data_64_t info;
        mach_msg_type_number_t cnt = VM_REGION_SUBMAP_INFO_COUNT_64;
        kern_return_t kr = mach_vm_region_recurse(task, &addr, &sz, &depth,
                           (vm_region_recurse_info_t)&info, &cnt);
        if (kr != KERN_SUCCESS) break;

        BOOL rw = (info.protection & VM_PROT_READ)    &&
                  (info.protection & VM_PROT_WRITE)   &&
                 !(info.protection & VM_PROT_EXECUTE);

        if (rw && sz >= 8 && sz <= 256*1024*1024) {
            uintptr_t end = (uintptr_t)(addr + sz) - 8;
            for (uintptr_t p = (uintptr_t)addr; p <= end; p += 4) {
                float fa = *(float *)p;
                float fb = *(float *)(p + 4);
                if (isfinite(fa) && isfinite(fb) &&
                    fabsf(fa - a) <= tolA &&
                    fabsf(fb - b) <= tolB)
                    return p;
            }
        }
        addr += sz;
    }
    return 0;
}

// ─────────────────────────────────────────────────────────────
//  §4  FEATURE SCAN
//  Pattern rationale (derived from deobfuscated GG script):
//
//  HeadHitbox  → Unity CharacterController radius ≈ 0.018f,
//                followed by 0.0f padding in the CapsuleCollider struct
//  BodyHitbox  → offset float -0.013f (centre offset) beside 0.1985f radius
//  Gravity Y   → Physics.gravity.y = -9.81f  (pair: 0,−9.81)
//  Smoke       → ParticleSystem startSize / density ≈ 20.625f
//  Flash       → PostProcess flash intensity stored as (5.0f, 5.0f) pair
//  WallCol     → CapsuleCollider radius 0.45f beside height 1.39f
//  EquipTO     → equipment timeout float ≈ 0.03f
//  WalkSpeed   → CharacterController.minMoveDistance / stepOffset ≈ 1.39f
//  JumpImpulse → Rigidbody addForce magnitude ≈ 5.5f (Unity default)
//  TimeScale   → Time.timeScale = 1.0f  (unique singleton, scan refinement needed)
// ─────────────────────────────────────────────────────────────

static void scan_all(void) {
    NSLog(@"[COCheat] ── scanning memory ──");

    // HeadHitbox: look for (0.018, 0.0) pair
    {
        uintptr_t p = scan_float_pair(0.018f, 0.004f, 0.0f, 0.003f);
        if (p) {
            gCache.headHitbox     = p;
            gCache.headHitboxOrig = mem_rf(p);
            NSLog(@"[COCheat] HeadHitbox  → 0x%lx (%.4f)", p, gCache.headHitboxOrig);
        } else NSLog(@"[COCheat] HeadHitbox  → NOT FOUND");
    }

    // BodyHitbox: look for (-0.013, 0.1985) pair
    {
        uintptr_t p = scan_float_pair(-0.013f, 0.004f, 0.1985f, 0.01f);
        if (p) {
            gCache.bodyHitbox     = p;
            gCache.bodyHitboxOrig = mem_rf(p);
            NSLog(@"[COCheat] BodyHitbox  → 0x%lx (%.4f)", p, gCache.bodyHitboxOrig);
        } else NSLog(@"[COCheat] BodyHitbox  → NOT FOUND");
    }

    // Gravity Y: scan pair (0.0, -9.81)
    {
        uintptr_t p = scan_float_pair(0.0f, 0.01f, -9.81f, 0.05f);
        if (!p) p = scan_float_pair(-9.81f, 0.05f, 0.0f, 0.01f);
        if (p) {
            // pick whichever component is -9.81
            float fa = mem_rf(p), fb = mem_rf(p + 4);
            gCache.gravityY     = (fabsf(fb + 9.81f) < 0.1f) ? p + 4 : p;
            gCache.gravityYOrig = mem_rf(gCache.gravityY);
            NSLog(@"[COCheat] GravityY    → 0x%lx (%.4f)", gCache.gravityY, gCache.gravityYOrig);
        } else NSLog(@"[COCheat] GravityY    → NOT FOUND");
    }

    // NoSmoke: particle density 20.625
    {
        uintptr_t p = scan_single_float(20.625f, 0.5f);
        if (p) {
            gCache.smoke     = p;
            gCache.smokeOrig = mem_rf(p);
            NSLog(@"[COCheat] Smoke       → 0x%lx (%.4f)", p, gCache.smokeOrig);
        } else NSLog(@"[COCheat] Smoke       → NOT FOUND");
    }

    // NoFlash: flash intensity pair (5.0, 5.0)
    {
        uintptr_t p = scan_float_pair(5.0f, 0.05f, 5.0f, 0.05f);
        if (p) {
            gCache.flash     = p;
            gCache.flashOrig = mem_rf(p);
            NSLog(@"[COCheat] Flash       → 0x%lx (%.4f)", p, gCache.flashOrig);
        } else NSLog(@"[COCheat] Flash       → NOT FOUND");
    }

    // WallCollision: (0.45, 1.39) — col radius + player height
    {
        uintptr_t p = scan_float_pair(0.45f, 0.02f, 1.39f, 0.05f);
        if (p) {
            gCache.wallCol     = p;
            gCache.wallColOrig = mem_rf(p);
            NSLog(@"[COCheat] WallCol     → 0x%lx (%.4f)", p, gCache.wallColOrig);
        } else NSLog(@"[COCheat] WallCol     → NOT FOUND");
    }

    // EquipTimeout: 0.03f
    {
        uintptr_t p = scan_single_float(0.03f, 0.002f);
        if (p) {
            gCache.equipTimeout     = p;
            gCache.equipTimeoutOrig = mem_rf(p);
            NSLog(@"[COCheat] EquipTimeout → 0x%lx (%.4f)", p, gCache.equipTimeoutOrig);
        } else NSLog(@"[COCheat] EquipTimeout → NOT FOUND");
    }

    // WalkSpeed (also used for fly): 1.39f
    {
        uintptr_t p = scan_single_float(1.39f, 0.01f);
        if (p) {
            gCache.walkSpeed     = p;
            gCache.walkSpeedOrig = mem_rf(p);
            NSLog(@"[COCheat] WalkSpeed   → 0x%lx (%.4f)", p, gCache.walkSpeedOrig);
        } else NSLog(@"[COCheat] WalkSpeed   → NOT FOUND");
    }

    // JumpImpulse: Unity default addForce ≈ 5.5f
    {
        uintptr_t p = scan_float_pair(5.5f, 0.3f, 0.0f, 0.05f);
        if (!p) p = scan_single_float(5.5f, 0.3f);
        if (p) {
            gCache.jumpImpulse     = p;
            gCache.jumpImpulseOrig = mem_rf(p);
            NSLog(@"[COCheat] JumpImpulse → 0x%lx (%.4f)", p, gCache.jumpImpulseOrig);
        } else NSLog(@"[COCheat] JumpImpulse → NOT FOUND");
    }

    // TimeScale: Unity Time.timeScale = 1.0f
    // Avoid matching every 1.0f — look for (1.0, 0.0166) pair (timeScale, fixedDeltaTime ~60fps)
    {
        uintptr_t p = scan_float_pair(1.0f, 0.005f, 0.01666f, 0.003f);
        if (p) {
            gCache.timeScale     = p;          // first float = timeScale
            gCache.timeScaleOrig = mem_rf(p);
            NSLog(@"[COCheat] TimeScale   → 0x%lx (%.4f)", p, gCache.timeScaleOrig);
        } else NSLog(@"[COCheat] TimeScale   → NOT FOUND");
    }

    gCache.found = YES;
    NSLog(@"[COCheat] ── scan complete ──");
}

// ─────────────────────────────────────────────────────────────
//  §5  VALUE TABLES  (maps level 1–10 to concrete floats)
// ─────────────────────────────────────────────────────────────

static const float kFlyTable[11]  = {0,  2.f,  3.f,  4.5f,  6.f,  8.f, 10.f, 13.f, 16.f, 20.f, 25.f};
static const float kJumpTable[11] = {0,  6.f,  8.f, 10.f,  12.5f,15.f, 18.f, 22.f, 27.f, 33.f, 40.f};
static const float kTimeTable[11] = {0,  1.5f, 2.f,  2.5f,  3.f,  3.5f, 4.f,  4.5f, 5.f,  6.f,  8.f};

static inline float lvl(const float *table, int lv) {
    if (lv < 1) lv = 1;
    if (lv > 10) lv = 10;
    return table[lv];
}

// ─────────────────────────────────────────────────────────────
//  §6  ANTI-BAN HELPERS
// ─────────────────────────────────────────────────────────────

// Add tiny random offset so the patched value never looks identical
// across samples — defeats static-value detection heuristics.
static float jitter(float v, float mag) {
    uint32_t r = arc4random_uniform(1000);
    return v + (((float)r / 1000.f) - 0.5f) * mag;
}

// ─────────────────────────────────────────────────────────────
//  §7  APPLY / RESTORE
// ─────────────────────────────────────────────────────────────

static void restore_all(void) {
    if (!gCache.found) return;
    if (gCache.headHitbox)    mem_wf(gCache.headHitbox,    gCache.headHitboxOrig);
    if (gCache.bodyHitbox)    mem_wf(gCache.bodyHitbox,    gCache.bodyHitboxOrig);
    if (gCache.gravityY)      mem_wf(gCache.gravityY,      gCache.gravityYOrig);
    if (gCache.smoke)         mem_wf(gCache.smoke,         gCache.smokeOrig);
    if (gCache.flash)       { mem_wf(gCache.flash,         gCache.flashOrig);
                              mem_wf(gCache.flash + 4,     5.0f); }
    if (gCache.wallCol)       mem_wf(gCache.wallCol,       gCache.wallColOrig);
    if (gCache.equipTimeout)  mem_wf(gCache.equipTimeout,  gCache.equipTimeoutOrig);
    if (gCache.walkSpeed)     mem_wf(gCache.walkSpeed,     gCache.walkSpeedOrig);
    if (gCache.jumpImpulse)   mem_wf(gCache.jumpImpulse,   gCache.jumpImpulseOrig);
    if (gCache.timeScale)     mem_wf(gCache.timeScale,     gCache.timeScaleOrig);
}

static void apply_all(void) {
    if (!gCache.found) return;

    // Safe mode: only visually-safe cheats (client-side only)
    BOOL safe = gState.safeMode;

    // ── Visual / client-safe ──────────────────────────────────
    if (gCache.smoke) {
        mem_wf(gCache.smoke, gState.noSmoke ? 0.0f : gCache.smokeOrig);
    }
    if (gCache.flash) {
        if (gState.noFlash) {
            mem_wf(gCache.flash,     0.0f);
            mem_wf(gCache.flash + 4, 0.0f);
        } else {
            mem_wf(gCache.flash,     gCache.flashOrig);
            mem_wf(gCache.flash + 4, 5.0f);
        }
    }

    // ── Hitboxes (risky but not always server-checked) ────────
    if (gCache.headHitbox) {
        mem_wf(gCache.headHitbox,
               gState.headHitbox ? jitter(0.45f, 0.002f) : gCache.headHitboxOrig);
    }
    if (gCache.bodyHitbox) {
        mem_wf(gCache.bodyHitbox,
               gState.bodyHitbox ? jitter(0.35f, 0.002f) : gCache.bodyHitboxOrig);
    }

    // ── Server-visible cheats (disabled in safe mode) ─────────
    if (!safe) {
        if (gCache.gravityY) {
            mem_wf(gCache.gravityY, gState.noGravity ? 0.0f : gCache.gravityYOrig);
        }
        if (gCache.wallCol) {
            mem_wf(gCache.wallCol,
                   gState.passThroughWalls ? -99999.0f : gCache.wallColOrig);
        }
        if (gCache.equipTimeout) {
            mem_wf(gCache.equipTimeout, gState.noEquipTimeout ? 0.0f : gCache.equipTimeoutOrig);
        }
        if (gCache.walkSpeed) {
            if (gState.flyLevel > 0)
                mem_wf(gCache.walkSpeed, jitter(lvl(kFlyTable, gState.flyLevel), 0.05f));
            else
                mem_wf(gCache.walkSpeed, gCache.walkSpeedOrig);
        }
        if (gCache.jumpImpulse) {
            if (gState.jumpLevel > 0)
                mem_wf(gCache.jumpImpulse, jitter(lvl(kJumpTable, gState.jumpLevel), 0.05f));
            else
                mem_wf(gCache.jumpImpulse, gCache.jumpImpulseOrig);
        }
        if (gCache.timeScale) {
            if (gState.timeLevel > 0)
                mem_wf(gCache.timeScale, lvl(kTimeTable, gState.timeLevel));
            else
                mem_wf(gCache.timeScale, gCache.timeScaleOrig);
        }
    } else {
        // safe mode: restore all server-visible values
        if (gCache.gravityY)     mem_wf(gCache.gravityY,     gCache.gravityYOrig);
        if (gCache.wallCol)      mem_wf(gCache.wallCol,      gCache.wallColOrig);
        if (gCache.equipTimeout) mem_wf(gCache.equipTimeout, gCache.equipTimeoutOrig);
        if (gCache.walkSpeed)    mem_wf(gCache.walkSpeed,    gCache.walkSpeedOrig);
        if (gCache.jumpImpulse)  mem_wf(gCache.jumpImpulse,  gCache.jumpImpulseOrig);
        if (gCache.timeScale)    mem_wf(gCache.timeScale,    gCache.timeScaleOrig);
    }
}

// ─────────────────────────────────────────────────────────────
//  §8  ANTI-BAN TICK  (called every second from background thread)
//  C-Ops sends stat packets roughly every 28 s.
//  We silently restore all server-visible values for 500 ms
//  just before that window, then re-apply.
// ─────────────────────────────────────────────────────────────

static BOOL gInTelemetryWindow = NO;

static void anti_ban_tick(void) {
    pthread_mutex_lock(&gMtx);

    NSTimeInterval t  = [[NSDate date] timeIntervalSince1970];
    double         cy = fmod(t, 28.0);   // 28-second cycle

    if (cy >= 27.2 && cy < 27.7) {
        // Telemetry window: restore
        if (!gInTelemetryWindow) {
            gInTelemetryWindow = YES;
            restore_all();
        }
    } else {
        // Normal window: apply cheats + jitter every 3 s
        if (gInTelemetryWindow) {
            gInTelemetryWindow = NO;
        }
        static NSTimeInterval lastJitter = 0;
        if (t - lastJitter >= 3.0) {
            apply_all();
            lastJitter = t;
        }
    }
    pthread_mutex_unlock(&gMtx);
}

// ─────────────────────────────────────────────────────────────
//  §9  BACKGROUND WORKER THREAD
// ─────────────────────────────────────────────────────────────

static void *cheat_thread(void *) {
    // Wait 8 s for Unity to fully initialise before scanning
    [NSThread sleepForTimeInterval:8.0];
    scan_all();
    apply_all();

    while (1) {
        [NSThread sleepForTimeInterval:1.0];
        anti_ban_tick();
    }
    return nullptr;
}

// ─────────────────────────────────────────────────────────────
//  §10  UI — floating draggable menu
// ─────────────────────────────────────────────────────────────

@interface COMenuVC : UIViewController
@end

@interface COFloatButton : UIButton
@property CGPoint lastTouch;
@end

@implementation COFloatButton
- (void)touchesMoved:(NSSet<UITouch *> *)touches withEvent:(UIEvent *)event {
    UITouch *t = touches.anyObject;
    CGPoint cur  = [t locationInView:self.superview];
    CGPoint prev = [t previousLocationInView:self.superview];
    CGRect f = self.frame;
    f.origin.x += cur.x - prev.x;
    f.origin.y += cur.y - prev.y;
    self.frame = f;
}
@end

// ── Row builder helpers ───────────────────────────────────────

static UILabel *makeLabel(NSString *txt, CGRect frame) {
    UILabel *l = [[UILabel alloc] initWithFrame:frame];
    l.text      = txt;
    l.textColor = [UIColor whiteColor];
    l.font      = [UIFont systemFontOfSize:13 weight:UIFontWeightMedium];
    return l;
}

static UISwitch *makeSwitch(CGRect frame, id target, SEL action) {
    UISwitch *s  = [[UISwitch alloc] initWithFrame:frame];
    s.onTintColor = [UIColor colorWithRed:0.2 green:0.8 blue:0.4 alpha:1];
    [s addTarget:target action:action forControlEvents:UIControlEventValueChanged];
    return s;
}

static UISlider *makeSlider(CGRect frame, id target, SEL action) {
    UISlider *sl = [[UISlider alloc] initWithFrame:frame];
    sl.minimumValue = 1;  sl.maximumValue = 10;  sl.value = 1;
    sl.tintColor    = [UIColor colorWithRed:0.2 green:0.8 blue:0.4 alpha:1];
    [sl addTarget:target action:action forControlEvents:UIControlEventValueChanged];
    return sl;
}

// ─────────────────────────────────────────────────────────────

@interface COMenuVC ()
// switches
@property (nonatomic) UISwitch *swHead;
@property (nonatomic) UISwitch *swBody;
@property (nonatomic) UISwitch *swGrav;
@property (nonatomic) UISwitch *swSmoke;
@property (nonatomic) UISwitch *swFlash;
@property (nonatomic) UISwitch *swWall;
@property (nonatomic) UISwitch *swEquip;
@property (nonatomic) UISwitch *swSafe;
// sliders
@property (nonatomic) UISlider *slFly;
@property (nonatomic) UISlider *slJump;
@property (nonatomic) UISlider *slTime;
// labels for slider values
@property (nonatomic) UILabel  *lblFlyVal;
@property (nonatomic) UILabel  *lblJumpVal;
@property (nonatomic) UILabel  *lblTimeVal;
// rescan button
@property (nonatomic) UIButton *btnRescan;
// status label
@property (nonatomic) UILabel  *lblStatus;
@end

@implementation COMenuVC

- (void)viewDidLoad {
    [super viewDidLoad];

    CGFloat W = 310, pad = 12, rowH = 36, sliderH = 28;
    CGFloat y = 0;

    // ── header ──
    UILabel *title = [[UILabel alloc] initWithFrame:CGRectMake(0, y, W, 44)];
    title.text          = @"☕ CritOps Cheat  |  by Coffee (iOS port)";
    title.textColor     = [UIColor colorWithRed:0.2 green:0.8 blue:0.4 alpha:1];
    title.font          = [UIFont systemFontOfSize:12 weight:UIFontWeightBold];
    title.textAlignment = NSTextAlignmentCenter;
    [self.view addSubview:title];
    y += 44;

    // ── separator ──
    UIView *sep = [[UIView alloc] initWithFrame:CGRectMake(pad, y, W - pad*2, 1)];
    sep.backgroundColor = [UIColor colorWithWhite:1 alpha:0.15];
    [self.view addSubview:sep];
    y += 6;

    // ── helper lambda to add a toggle row ──────────────────────
    void (^addRow)(NSString *, UISwitch **) = ^(NSString *name, UISwitch **swOut) {
        UILabel  *lbl = makeLabel(name, CGRectMake(pad, y, 220, rowH));
        UISwitch *sw  = makeSwitch(CGRectMake(W - 60 - pad, y + 3, 60, 30),
                                   self, @selector(switchChanged:));
        [self.view addSubview:lbl];
        [self.view addSubview:sw];
        if (swOut) *swOut = sw;
        y += rowH;
    };

    // ── toggle rows ─────────────────────────────────────────────
    addRow(@"😵  Head Hitbox",           &_swHead);
    addRow(@"👕  Body Hitbox",           &_swBody);
    addRow(@"🍃  No Gravity",            &_swGrav);
    addRow(@"☁️   No Smoke",             &_swSmoke);
    addRow(@"👀  No Flash",              &_swFlash);
    addRow(@"👻  Pass Through Walls",    &_swWall);
    addRow(@"⏱️   No Equip Timeout",    &_swEquip);
    addRow(@"🛡️   Safe Mode (anti-ban)", &_swSafe);

    y += 4;
    [self.view addSubview:[[UIView alloc] init]]; // spacer

    // ── slider rows ─────────────────────────────────────────────
    void (^addSlider)(NSString *, UISlider **, UILabel **, SEL) =
    ^(NSString *name, UISlider **slOut, UILabel **lblOut, SEL action) {
        UILabel  *lbl  = makeLabel(name, CGRectMake(pad, y, 140, sliderH));
        UILabel  *val  = makeLabel(@"OFF", CGRectMake(W - 60 - pad, y, 50, sliderH));
        val.textAlignment = NSTextAlignmentRight;
        val.textColor     = [UIColor colorWithRed:0.2 green:0.8 blue:0.4 alpha:1];
        UISlider *sl   = makeSlider(CGRectMake(145, y, W - 145 - 70, sliderH), self, action);
        sl.value = 0;  sl.minimumValue = 0;
        [self.view addSubview:lbl];
        [self.view addSubview:val];
        [self.view addSubview:sl];
        if (slOut)  *slOut  = sl;
        if (lblOut) *lblOut = val;
        y += sliderH + 6;
    };

    addSlider(@"🚁  Fly",       &_slFly,  &_lblFlyVal,  @selector(sliderFly:));
    addSlider(@"🐇  Super Jump",&_slJump, &_lblJumpVal, @selector(sliderJump:));
    addSlider(@"⌛  Fast Time", &_slTime, &_lblTimeVal, @selector(sliderTime:));

    y += 6;

    // ── rescan button ────────────────────────────────────────────
    _btnRescan = [UIButton buttonWithType:UIButtonTypeSystem];
    _btnRescan.frame = CGRectMake(pad, y, W - pad*2, 34);
    [_btnRescan setTitle:@"🔍  Re-scan Memory" forState:UIControlStateNormal];
    [_btnRescan setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    _btnRescan.backgroundColor = [UIColor colorWithRed:0.15 green:0.5 blue:0.3 alpha:1];
    _btnRescan.layer.cornerRadius = 8;
    [_btnRescan addTarget:self action:@selector(rescan) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:_btnRescan];
    y += 40;

    // ── status label ─────────────────────────────────────────────
    _lblStatus = makeLabel(@"⏳ Waiting for scan...", CGRectMake(pad, y, W - pad*2, 24));
    _lblStatus.font = [UIFont systemFontOfSize:11];
    _lblStatus.textColor = [UIColor colorWithWhite:0.6 alpha:1];
    [self.view addSubview:_lblStatus];
    y += 26;

    // ── size the container ────────────────────────────────────────
    self.view.frame = CGRectMake(0, 0, W, y + 8);
    self.view.backgroundColor = [UIColor colorWithRed:0.08 green:0.08 blue:0.10 alpha:0.95];
    self.view.layer.cornerRadius = 12;
    self.view.clipsToBounds = YES;

    // Poll for scan completion
    [NSTimer scheduledTimerWithTimeInterval:2.0 target:self
             selector:@selector(pollScanStatus) userInfo:nil repeats:YES];
}

- (void)pollScanStatus {
    if (gCache.found) {
        int found = (gCache.headHitbox    ? 1 : 0) +
                    (gCache.bodyHitbox    ? 1 : 0) +
                    (gCache.gravityY      ? 1 : 0) +
                    (gCache.smoke         ? 1 : 0) +
                    (gCache.flash         ? 1 : 0) +
                    (gCache.wallCol       ? 1 : 0) +
                    (gCache.equipTimeout  ? 1 : 0) +
                    (gCache.walkSpeed     ? 1 : 0) +
                    (gCache.jumpImpulse   ? 1 : 0) +
                    (gCache.timeScale     ? 1 : 0);
        _lblStatus.textColor = [UIColor colorWithRed:0.2 green:0.9 blue:0.4 alpha:1];
        _lblStatus.text = [NSString stringWithFormat:@"✅ %d/10 addresses found", found];
    }
}

// ── control callbacks ─────────────────────────────────────────

- (void)switchChanged:(UISwitch *)sw {
    pthread_mutex_lock(&gMtx);
    if (sw == _swHead)  gState.headHitbox      = sw.on;
    if (sw == _swBody)  gState.bodyHitbox      = sw.on;
    if (sw == _swGrav)  gState.noGravity       = sw.on;
    if (sw == _swSmoke) gState.noSmoke         = sw.on;
    if (sw == _swFlash) gState.noFlash         = sw.on;
    if (sw == _swWall)  gState.passThroughWalls = sw.on;
    if (sw == _swEquip) gState.noEquipTimeout  = sw.on;
    if (sw == _swSafe)  gState.safeMode        = sw.on;
    apply_all();
    pthread_mutex_unlock(&gMtx);
}

- (void)sliderFly:(UISlider *)sl {
    pthread_mutex_lock(&gMtx);
    int lv = (int)roundf(sl.value);
    gState.flyLevel = lv;
    _lblFlyVal.text = lv > 0 ? [NSString stringWithFormat:@"Lv %d", lv] : @"OFF";
    apply_all();
    pthread_mutex_unlock(&gMtx);
}

- (void)sliderJump:(UISlider *)sl {
    pthread_mutex_lock(&gMtx);
    int lv = (int)roundf(sl.value);
    gState.jumpLevel = lv;
    _lblJumpVal.text = lv > 0 ? [NSString stringWithFormat:@"Lv %d", lv] : @"OFF";
    apply_all();
    pthread_mutex_unlock(&gMtx);
}

- (void)sliderTime:(UISlider *)sl {
    pthread_mutex_lock(&gMtx);
    int lv = (int)roundf(sl.value);
    gState.timeLevel = lv;
    _lblTimeVal.text = lv > 0 ? [NSString stringWithFormat:@"Lv %d", lv] : @"OFF";
    apply_all();
    pthread_mutex_unlock(&gMtx);
}

- (void)rescan {
    _lblStatus.textColor = [UIColor colorWithWhite:0.6 alpha:1];
    _lblStatus.text = @"🔄 Re-scanning...";
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        gCache.found = NO;
        scan_all();
        apply_all();
    });
}

@end

// ─────────────────────────────────────────────────────────────
//  §11  FLOATING WINDOW + BUTTON
// ─────────────────────────────────────────────────────────────

static UIWindow   *gMenuWindow  = nil;
static UIWindow   *gBtnWindow   = nil;
static COMenuVC   *gMenuVC      = nil;
static BOOL        gMenuVisible = NO;

static void show_menu(BOOL show) {
    gMenuVisible = show;
    gMenuWindow.hidden  = !show;
    if (show) [gMenuWindow makeKeyAndVisible];
}

static void launch_ui(void) {
    // Floating toggle button
    CGRect screen = [UIScreen mainScreen].bounds;

    gBtnWindow = [[UIWindow alloc] initWithFrame:CGRectMake(screen.size.width - 70, 80, 54, 54)];
    gBtnWindow.windowLevel = UIWindowLevelAlert + 1000;
    gBtnWindow.backgroundColor = [UIColor clearColor];

    COFloatButton *fab = [COFloatButton buttonWithType:UIButtonTypeCustom];
    fab.frame = CGRectMake(0, 0, 54, 54);
    [fab setTitle:@"☕" forState:UIControlStateNormal];
    fab.titleLabel.font   = [UIFont systemFontOfSize:28];
    fab.backgroundColor   = [UIColor colorWithRed:0.08 green:0.08 blue:0.10 alpha:0.92];
    fab.layer.cornerRadius = 27;
    fab.layer.borderWidth  = 1.5;
    fab.layer.borderColor  = [UIColor colorWithRed:0.2 green:0.8 blue:0.4 alpha:1].CGColor;
    [fab addTarget:nil action:@selector(fabTapped) forControlEvents:UIControlEventTouchUpInside];
    [gBtnWindow addSubview:fab];
    gBtnWindow.hidden = NO;
    [gBtnWindow makeKeyAndVisible];

    // Menu window
    gMenuVC = [[COMenuVC alloc] init];
    [gMenuVC loadViewIfNeeded];
    CGFloat mW = gMenuVC.view.frame.size.width;
    CGFloat mH = gMenuVC.view.frame.size.height;
    CGFloat mX = (screen.size.width  - mW) / 2;
    CGFloat mY = (screen.size.height - mH) / 2;

    gMenuWindow = [[UIWindow alloc] initWithFrame:CGRectMake(mX, mY, mW, mH)];
    gMenuWindow.windowLevel    = UIWindowLevelAlert + 999;
    gMenuWindow.rootViewController = gMenuVC;
    gMenuWindow.backgroundColor    = [UIColor clearColor];
    gMenuWindow.hidden             = YES;

    // allow touch pass-through to game when menu is hidden
    [fab addTarget:nil action:@selector(fabTapped) forControlEvents:UIControlEventTouchUpInside];
}

// Can't use objc_msgSend trick cleanly here — use a global function instead
// and wire the button to it via a trampoline object.

@interface COBtnTarget : NSObject
@end
@implementation COBtnTarget
- (void)fabTapped { show_menu(!gMenuVisible); }
@end
static COBtnTarget *gBtnTarget = nil;

// ─────────────────────────────────────────────────────────────
//  §12  ENTRY POINT
// ─────────────────────────────────────────────────────────────

__attribute__((constructor))
static void dylib_init(void) {
    NSLog(@"[COCheat] dylib loaded — waiting for UIKit...");

    // Delay UI until main run loop is live
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        gBtnTarget = [[COBtnTarget alloc] init];
        launch_ui();
        NSLog(@"[COCheat] UI ready");
    });

    // Start background memory scanner + anti-ban thread
    pthread_t tid;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_create(&tid, &attr, cheat_thread, nullptr);
    pthread_attr_destroy(&attr);
}
