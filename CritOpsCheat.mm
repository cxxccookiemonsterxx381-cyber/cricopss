// CritOpsCheat.mm — Critical Ops iOS Cheat Dylib
// Non-JB IPA injection | iOS 14+ ARM64
// Fixed for Xcode 26 / iOS 26 SDK

#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <sys/mman.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#include <pthread.h>

// ─── STATE ───────────────────────────────────────────────────
typedef struct {
    BOOL headHitbox, bodyHitbox, noGravity, noSmoke;
    BOOL noFlash, passThroughWalls, noEquipTimeout, safeMode;
    int  flyLevel, jumpLevel, timeLevel;
} CheatState;

typedef struct {
    uintptr_t headHitbox, bodyHitbox, gravityY;
    uintptr_t smoke, flash, wallCol, equipTimeout;
    uintptr_t walkSpeed, jumpImpulse, timeScale;
    float headHitboxOrig, bodyHitboxOrig, gravityYOrig;
    float smokeOrig, flashOrig, wallColOrig, equipTimeoutOrig;
    float walkSpeedOrig, jumpImpulseOrig, timeScaleOrig;
    BOOL found;
} AddrCache;

static CheatState      gState  = {};
static AddrCache       gCache  = {};
static pthread_mutex_t gMtx    = PTHREAD_MUTEX_INITIALIZER;

// ─── MEMORY ──────────────────────────────────────────────────
static void mem_unlock(uintptr_t addr) {
    uintptr_t page = addr & ~0x3FFFUL;
    mprotect((void *)page, 0x4000, PROT_READ | PROT_WRITE | PROT_EXEC);
}
static float mem_rf(uintptr_t addr) { return *(volatile float *)addr; }
static void  mem_wf(uintptr_t addr, float v) {
    if (!addr) return;
    mem_unlock(addr);
    *(volatile float *)addr = v;
    __asm__ volatile("dc cvau, %0\nic ivau, %0\ndsb ish\nisb\n" :: "r"(addr) : "memory");
}

// ─── SCANNER ─────────────────────────────────────────────────
static uintptr_t scan_single(float target, float tol) {
    mach_port_t        task  = mach_task_self();
    mach_vm_address_t  addr  = 0;
    mach_vm_size_t     sz    = 0;
    uint32_t           depth = 1;
    while (1) {
        vm_region_submap_info_data_64_t info;
        mach_msg_type_number_t cnt = VM_REGION_SUBMAP_INFO_COUNT_64;
        kern_return_t kr = mach_vm_region_recurse(task, &addr, &sz, &depth,
                           (vm_region_recurse_info_t)&info, &cnt);
        if (kr != KERN_SUCCESS) break;
        BOOL rw = (info.protection & VM_PROT_READ) &&
                  (info.protection & VM_PROT_WRITE) &&
                 !(info.protection & VM_PROT_EXECUTE);
        if (rw && sz >= 4 && sz <= 256*1024*1024) {
            uintptr_t end = (uintptr_t)(addr + sz) - 4;
            for (uintptr_t p = (uintptr_t)addr; p <= end; p += 4) {
                float v = *(float *)p;
                if (isfinite(v) && fabsf(v - target) <= tol) return p;
            }
        }
        addr += sz;
    }
    return 0;
}

static uintptr_t scan_pair(float a, float ta, float b, float tb) {
    mach_port_t        task  = mach_task_self();
    mach_vm_address_t  addr  = 0;
    mach_vm_size_t     sz    = 0;
    uint32_t           depth = 1;
    while (1) {
        vm_region_submap_info_data_64_t info;
        mach_msg_type_number_t cnt = VM_REGION_SUBMAP_INFO_COUNT_64;
        kern_return_t kr = mach_vm_region_recurse(task, &addr, &sz, &depth,
                           (vm_region_recurse_info_t)&info, &cnt);
        if (kr != KERN_SUCCESS) break;
        BOOL rw = (info.protection & VM_PROT_READ) &&
                  (info.protection & VM_PROT_WRITE) &&
                 !(info.protection & VM_PROT_EXECUTE);
        if (rw && sz >= 8 && sz <= 256*1024*1024) {
            uintptr_t end = (uintptr_t)(addr + sz) - 8;
            for (uintptr_t p = (uintptr_t)addr; p <= end; p += 4) {
                float fa = *(float *)p, fb = *(float *)(p+4);
                if (isfinite(fa) && isfinite(fb) &&
                    fabsf(fa-a) <= ta && fabsf(fb-b) <= tb) return p;
            }
        }
        addr += sz;
    }
    return 0;
}

// ─── SCAN ALL ────────────────────────────────────────────────
static void scan_all(void) {
    NSLog(@"[COCheat] scanning...");
    uintptr_t p;

    p = scan_pair(0.018f, 0.004f, 0.0f, 0.003f);
    if (p) { gCache.headHitbox = p; gCache.headHitboxOrig = mem_rf(p); }

    p = scan_pair(-0.013f, 0.004f, 0.1985f, 0.01f);
    if (p) { gCache.bodyHitbox = p; gCache.bodyHitboxOrig = mem_rf(p); }

    p = scan_pair(0.0f, 0.01f, -9.81f, 0.05f);
    if (!p) p = scan_pair(-9.81f, 0.05f, 0.0f, 0.01f);
    if (p) {
        float fa = mem_rf(p), fb = mem_rf(p+4);
        gCache.gravityY     = (fabsf(fb+9.81f) < 0.1f) ? p+4 : p;
        gCache.gravityYOrig = mem_rf(gCache.gravityY);
    }

    p = scan_single(20.625f, 0.5f);
    if (p) { gCache.smoke = p; gCache.smokeOrig = mem_rf(p); }

    p = scan_pair(5.0f, 0.05f, 5.0f, 0.05f);
    if (p) { gCache.flash = p; gCache.flashOrig = mem_rf(p); }

    p = scan_pair(0.45f, 0.02f, 1.39f, 0.05f);
    if (p) { gCache.wallCol = p; gCache.wallColOrig = mem_rf(p); }

    p = scan_single(0.03f, 0.002f);
    if (p) { gCache.equipTimeout = p; gCache.equipTimeoutOrig = mem_rf(p); }

    p = scan_single(1.39f, 0.01f);
    if (p) { gCache.walkSpeed = p; gCache.walkSpeedOrig = mem_rf(p); }

    p = scan_pair(5.5f, 0.3f, 0.0f, 0.05f);
    if (!p) p = scan_single(5.5f, 0.3f);
    if (p) { gCache.jumpImpulse = p; gCache.jumpImpulseOrig = mem_rf(p); }

    p = scan_pair(1.0f, 0.005f, 0.01666f, 0.003f);
    if (p) { gCache.timeScale = p; gCache.timeScaleOrig = mem_rf(p); }

    gCache.found = YES;
    NSLog(@"[COCheat] scan done");
}

// ─── VALUE TABLES ────────────────────────────────────────────
static const float kFly[11]  = {0,2,3,4.5,6,8,10,13,16,20,25};
static const float kJump[11] = {0,6,8,10,12.5,15,18,22,27,33,40};
static const float kTime[11] = {0,1.5,2,2.5,3,3.5,4,4.5,5,6,8};
static float lvl(const float *t, int l) {
    if (l<1) l=1; if (l>10) l=10; return t[l];
}
static float jitter(float v, float m) {
    return v + (((float)(arc4random_uniform(1000))/1000.f)-0.5f)*m;
}

// ─── RESTORE / APPLY ─────────────────────────────────────────
static void restore_all(void) {
    if (!gCache.found) return;
    if (gCache.headHitbox)   mem_wf(gCache.headHitbox,   gCache.headHitboxOrig);
    if (gCache.bodyHitbox)   mem_wf(gCache.bodyHitbox,   gCache.bodyHitboxOrig);
    if (gCache.gravityY)     mem_wf(gCache.gravityY,     gCache.gravityYOrig);
    if (gCache.smoke)        mem_wf(gCache.smoke,        gCache.smokeOrig);
    if (gCache.flash)      { mem_wf(gCache.flash,        gCache.flashOrig);
                             mem_wf(gCache.flash+4,      5.0f); }
    if (gCache.wallCol)      mem_wf(gCache.wallCol,      gCache.wallColOrig);
    if (gCache.equipTimeout) mem_wf(gCache.equipTimeout, gCache.equipTimeoutOrig);
    if (gCache.walkSpeed)    mem_wf(gCache.walkSpeed,    gCache.walkSpeedOrig);
    if (gCache.jumpImpulse)  mem_wf(gCache.jumpImpulse,  gCache.jumpImpulseOrig);
    if (gCache.timeScale)    mem_wf(gCache.timeScale,    gCache.timeScaleOrig);
}

static void apply_all(void) {
    if (!gCache.found) return;
    BOOL safe = gState.safeMode;

    if (gCache.smoke)
        mem_wf(gCache.smoke, gState.noSmoke ? 0.0f : gCache.smokeOrig);
    if (gCache.flash) {
        mem_wf(gCache.flash,   gState.noFlash ? 0.0f : gCache.flashOrig);
        mem_wf(gCache.flash+4, gState.noFlash ? 0.0f : 5.0f);
    }
    if (gCache.headHitbox)
        mem_wf(gCache.headHitbox, gState.headHitbox ? jitter(0.45f,0.002f) : gCache.headHitboxOrig);
    if (gCache.bodyHitbox)
        mem_wf(gCache.bodyHitbox, gState.bodyHitbox ? jitter(0.35f,0.002f) : gCache.bodyHitboxOrig);

    if (!safe) {
        if (gCache.gravityY)
            mem_wf(gCache.gravityY, gState.noGravity ? 0.0f : gCache.gravityYOrig);
        if (gCache.wallCol)
            mem_wf(gCache.wallCol, gState.passThroughWalls ? -99999.0f : gCache.wallColOrig);
        if (gCache.equipTimeout)
            mem_wf(gCache.equipTimeout, gState.noEquipTimeout ? 0.0f : gCache.equipTimeoutOrig);
        if (gCache.walkSpeed)
            mem_wf(gCache.walkSpeed, gState.flyLevel>0 ? jitter(lvl(kFly,gState.flyLevel),0.05f) : gCache.walkSpeedOrig);
        if (gCache.jumpImpulse)
            mem_wf(gCache.jumpImpulse, gState.jumpLevel>0 ? jitter(lvl(kJump,gState.jumpLevel),0.05f) : gCache.jumpImpulseOrig);
        if (gCache.timeScale)
            mem_wf(gCache.timeScale, gState.timeLevel>0 ? lvl(kTime,gState.timeLevel) : gCache.timeScaleOrig);
    } else {
        if (gCache.gravityY)     mem_wf(gCache.gravityY,     gCache.gravityYOrig);
        if (gCache.wallCol)      mem_wf(gCache.wallCol,      gCache.wallColOrig);
        if (gCache.equipTimeout) mem_wf(gCache.equipTimeout, gCache.equipTimeoutOrig);
        if (gCache.walkSpeed)    mem_wf(gCache.walkSpeed,    gCache.walkSpeedOrig);
        if (gCache.jumpImpulse)  mem_wf(gCache.jumpImpulse,  gCache.jumpImpulseOrig);
        if (gCache.timeScale)    mem_wf(gCache.timeScale,    gCache.timeScaleOrig);
    }
}

// ─── ANTI-BAN TICK ───────────────────────────────────────────
static BOOL gInTelemetry = NO;
static void anti_ban_tick(void) {
    pthread_mutex_lock(&gMtx);
    NSTimeInterval t  = [[NSDate date] timeIntervalSince1970];
    double         cy = fmod(t, 28.0);
    if (cy >= 27.2 && cy < 27.7) {
        if (!gInTelemetry) { gInTelemetry = YES; restore_all(); }
    } else {
        static NSTimeInterval last = 0;
        if (gInTelemetry) gInTelemetry = NO;
        if (t - last >= 3.0) { apply_all(); last = t; }
    }
    pthread_mutex_unlock(&gMtx);
}

static void *cheat_thread(void *) {
    [NSThread sleepForTimeInterval:8.0];
    scan_all(); apply_all();
    while (1) { [NSThread sleepForTimeInterval:1.0]; anti_ban_tick(); }
    return nullptr;
}

// ─── UI ──────────────────────────────────────────────────────
@interface COMenuVC : UIViewController
@property UISwitch *swHead, *swBody, *swGrav, *swSmoke;
@property UISwitch *swFlash, *swWall, *swEquip, *swSafe;
@property UISlider *slFly, *slJump, *slTime;
@property UILabel  *lblFly, *lblJump, *lblTime, *lblStatus;
@end

@implementation COMenuVC
- (void)viewDidLoad {
    [super viewDidLoad];
    CGFloat W = 300, pad = 12, rowH = 38, slH = 30;
    __block CGFloat y = 0;

    self.view.backgroundColor = [UIColor colorWithRed:0.07 green:0.07 blue:0.09 alpha:0.96];
    self.view.layer.cornerRadius = 14;
    self.view.clipsToBounds = YES;

    // header
    UILabel *hdr = [[UILabel alloc] initWithFrame:CGRectMake(0, y, W, 42)];
    hdr.text = @"☕ CritOps Cheat";
    hdr.textAlignment = NSTextAlignmentCenter;
    hdr.textColor = [UIColor colorWithRed:0.2 green:0.85 blue:0.45 alpha:1];
    hdr.font = [UIFont boldSystemFontOfSize:14];
    [self.view addSubview:hdr]; y += 42;

    UIView *sep = [[UIView alloc] initWithFrame:CGRectMake(pad, y, W-pad*2, 1)];
    sep.backgroundColor = [UIColor colorWithWhite:1 alpha:0.1];
    [self.view addSubview:sep]; y += 6;

    // toggle row helper
    void (^row)(NSString*, UISwitch**) = ^(NSString *name, UISwitch **out) {
        UILabel *l = [[UILabel alloc] initWithFrame:CGRectMake(pad, y, 210, rowH)];
        l.text = name; l.textColor = [UIColor whiteColor];
        l.font = [UIFont systemFontOfSize:13];
        UISwitch *s = [[UISwitch alloc] initWithFrame:CGRectMake(W-60-pad, y+4, 0, 0)];
        s.onTintColor = [UIColor colorWithRed:0.2 green:0.85 blue:0.45 alpha:1];
        [s addTarget:self action:@selector(sw:) forControlEvents:UIControlEventValueChanged];
        [self.view addSubview:l]; [self.view addSubview:s];
        if (out) *out = s;
        y += rowH;
    };

    row(@"😵  Head Hitbox",           &_swHead);
    row(@"👕  Body Hitbox",           &_swBody);
    row(@"🍃  No Gravity",            &_swGrav);
    row(@"☁️   No Smoke",             &_swSmoke);
    row(@"👀  No Flash",              &_swFlash);
    row(@"👻  Pass Through Walls",    &_swWall);
    row(@"⏱️   No Equip Timeout",    &_swEquip);
    row(@"🛡️   Safe Mode",            &_swSafe);

    y += 4;

    // slider row helper
    void (^srow)(NSString*, UISlider**, UILabel**, SEL) =
    ^(NSString *name, UISlider **sOut, UILabel **lOut, SEL action) {
        UILabel *l = [[UILabel alloc] initWithFrame:CGRectMake(pad, y, 120, slH)];
        l.text = name; l.textColor = [UIColor whiteColor];
        l.font = [UIFont systemFontOfSize:12];
        UILabel *val = [[UILabel alloc] initWithFrame:CGRectMake(W-55-pad, y, 50, slH)];
        val.text = @"OFF"; val.textAlignment = NSTextAlignmentRight;
        val.textColor = [UIColor colorWithRed:0.2 green:0.85 blue:0.45 alpha:1];
        val.font = [UIFont systemFontOfSize:12];
        UISlider *sl = [[UISlider alloc] initWithFrame:CGRectMake(130, y, W-130-65, slH)];
        sl.minimumValue = 0; sl.maximumValue = 10; sl.value = 0;
        sl.tintColor = [UIColor colorWithRed:0.2 green:0.85 blue:0.45 alpha:1];
        [sl addTarget:self action:action forControlEvents:UIControlEventValueChanged];
        [self.view addSubview:l]; [self.view addSubview:val]; [self.view addSubview:sl];
        if (sOut) *sOut = sl; if (lOut) *lOut = val;
        y += slH + 8;
    };

    srow(@"🚁  Fly",        &_slFly,  &_lblFly,  @selector(slFly:));
    srow(@"🐇  Super Jump", &_slJump, &_lblJump, @selector(slJump:));
    srow(@"⌛  Fast Time",  &_slTime, &_lblTime, @selector(slTime:));

    y += 4;

    // rescan button
    UIButton *btn = [UIButton buttonWithType:UIButtonTypeSystem];
    btn.frame = CGRectMake(pad, y, W-pad*2, 34);
    [btn setTitle:@"🔍  Re-scan Memory" forState:UIControlStateNormal];
    [btn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    btn.backgroundColor = [UIColor colorWithRed:0.12 green:0.45 blue:0.25 alpha:1];
    btn.layer.cornerRadius = 8;
    [btn addTarget:self action:@selector(rescan) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:btn]; y += 40;

    // status
    _lblStatus = [[UILabel alloc] initWithFrame:CGRectMake(pad, y, W-pad*2, 22)];
    _lblStatus.text = @"⏳ Waiting for scan...";
    _lblStatus.textColor = [UIColor colorWithWhite:0.5 alpha:1];
    _lblStatus.font = [UIFont systemFontOfSize:11];
    [self.view addSubview:_lblStatus]; y += 24;

    self.view.frame = CGRectMake(0, 0, W, y+8);

    [NSTimer scheduledTimerWithTimeInterval:2 target:self
             selector:@selector(poll) userInfo:nil repeats:YES];
}

- (void)poll {
    if (!gCache.found) return;
    int n = (gCache.headHitbox?1:0)+(gCache.bodyHitbox?1:0)+(gCache.gravityY?1:0)+
            (gCache.smoke?1:0)+(gCache.flash?1:0)+(gCache.wallCol?1:0)+
            (gCache.equipTimeout?1:0)+(gCache.walkSpeed?1:0)+
            (gCache.jumpImpulse?1:0)+(gCache.timeScale?1:0);
    _lblStatus.textColor = [UIColor colorWithRed:0.2 green:0.9 blue:0.4 alpha:1];
    _lblStatus.text = [NSString stringWithFormat:@"✅ %d/10 addresses found", n];
}

- (void)sw:(UISwitch *)s {
    pthread_mutex_lock(&gMtx);
    if (s==_swHead)  gState.headHitbox       = s.on;
    if (s==_swBody)  gState.bodyHitbox       = s.on;
    if (s==_swGrav)  gState.noGravity        = s.on;
    if (s==_swSmoke) gState.noSmoke          = s.on;
    if (s==_swFlash) gState.noFlash          = s.on;
    if (s==_swWall)  gState.passThroughWalls = s.on;
    if (s==_swEquip) gState.noEquipTimeout   = s.on;
    if (s==_swSafe)  gState.safeMode         = s.on;
    apply_all();
    pthread_mutex_unlock(&gMtx);
}
- (void)slFly:(UISlider*)s {
    pthread_mutex_lock(&gMtx);
    int l=(int)roundf(s.value); gState.flyLevel=l;
    _lblFly.text = l>0?[NSString stringWithFormat:@"Lv%d",l]:@"OFF";
    apply_all(); pthread_mutex_unlock(&gMtx);
}
- (void)slJump:(UISlider*)s {
    pthread_mutex_lock(&gMtx);
    int l=(int)roundf(s.value); gState.jumpLevel=l;
    _lblJump.text = l>0?[NSString stringWithFormat:@"Lv%d",l]:@"OFF";
    apply_all(); pthread_mutex_unlock(&gMtx);
}
- (void)slTime:(UISlider*)s {
    pthread_mutex_lock(&gMtx);
    int l=(int)roundf(s.value); gState.timeLevel=l;
    _lblTime.text = l>0?[NSString stringWithFormat:@"Lv%d",l]:@"OFF";
    apply_all(); pthread_mutex_unlock(&gMtx);
}
- (void)rescan {
    _lblStatus.textColor = [UIColor colorWithWhite:0.5 alpha:1];
    _lblStatus.text = @"🔄 Re-scanning...";
    dispatch_async(dispatch_get_global_queue(0,0), ^{
        gCache.found = NO; scan_all(); apply_all();
    });
}
@end

// ─── FLOATING BUTTON + WINDOW ────────────────────────────────
static UIWindow  *gMenuWin = nil;
static COMenuVC  *gMenuVC  = nil;
static UIWindow  *gBtnWin  = nil;
static BOOL       gVisible = NO;

@interface COFab : UIButton
@end
@implementation COFab
- (void)touchesMoved:(NSSet<UITouch*>*)t withEvent:(UIEvent*)e {
    UITouch *u=[t anyObject];
    CGPoint c=[u locationInView:self.superview], p=[u previousLocationInView:self.superview];
    CGRect f=self.frame; f.origin.x+=c.x-p.x; f.origin.y+=c.y-p.y; self.frame=f;
}
@end

@interface COFabTarget : NSObject
- (void)tap;
@end
@implementation COFabTarget
- (void)tap { gVisible=!gVisible; gMenuWin.hidden=!gVisible;
               if(gVisible)[gMenuWin makeKeyAndVisible]; }
@end
static COFabTarget *gFabTarget = nil;

static void launch_ui(void) {
    CGRect sc = [UIScreen mainScreen].bounds;

    gBtnWin = [[UIWindow alloc] initWithFrame:CGRectMake(sc.size.width-70,80,54,54)];
    gBtnWin.windowLevel = UIWindowLevelAlert+1000;
    gBtnWin.backgroundColor = [UIColor clearColor];

    COFab *fab = [COFab buttonWithType:UIButtonTypeCustom];
    fab.frame = CGRectMake(0,0,54,54);
    [fab setTitle:@"☕" forState:UIControlStateNormal];
    fab.titleLabel.font = [UIFont systemFontOfSize:26];
    fab.backgroundColor = [UIColor colorWithRed:0.07 green:0.07 blue:0.09 alpha:0.93];
    fab.layer.cornerRadius = 27;
    fab.layer.borderWidth  = 1.5;
    fab.layer.borderColor  = [UIColor colorWithRed:0.2 green:0.85 blue:0.45 alpha:1].CGColor;
    gFabTarget = [[COFabTarget alloc] init];
    [fab addTarget:gFabTarget action:@selector(tap) forControlEvents:UIControlEventTouchUpInside];
    [gBtnWin addSubview:fab];
    gBtnWin.hidden = NO;
    [gBtnWin makeKeyAndVisible];

    gMenuVC = [[COMenuVC alloc] init];
    [gMenuVC loadViewIfNeeded];
    CGFloat mW=gMenuVC.view.frame.size.width, mH=gMenuVC.view.frame.size.height;
    gMenuWin = [[UIWindow alloc] initWithFrame:CGRectMake((sc.size.width-mW)/2,
                                                           (sc.size.height-mH)/2, mW, mH)];
    gMenuWin.windowLevel = UIWindowLevelAlert+999;
    gMenuWin.rootViewController = gMenuVC;
    gMenuWin.backgroundColor = [UIColor clearColor];
    gMenuWin.hidden = YES;
}

// ─── ENTRY ───────────────────────────────────────────────────
__attribute__((constructor))
static void dylib_init(void) {
    NSLog(@"[COCheat] loaded");
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(3.0*NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{ launch_ui(); });
    pthread_t tid; pthread_attr_t a;
    pthread_attr_init(&a);
    pthread_attr_setdetachstate(&a, PTHREAD_CREATE_DETACHED);
    pthread_create(&tid, &a, cheat_thread, nullptr);
    pthread_attr_destroy(&a);
}
