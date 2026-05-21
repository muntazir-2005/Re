#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import "fishhook.h"
#import <sys/sysctl.h>
#import <sys/utsname.h>
#import <dlfcn.h>

// مؤشرات أصلية
static int (*orig_sysctl)(int *, u_int, void *, size_t *, void *, size_t);
static int (*orig_sysctlbyname)(const char *, void *, size_t *, void *, size_t);
static char* (*orig_getenv)(const char *);
static int (*orig_uname)(struct utsname *);

// دوال بديلة مبسطة
static int _sysctl_h(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    if (namelen >= 2 && name[0] == CTL_KERN && name[1] == KERN_PROC) return -1;
    return orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen);
}
static int _sysctlbyname_h(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    if (name && strstr(name, "proc")) return -1;
    return orig_sysctlbyname(name, oldp, oldlenp, newp, newlen);
}
static char* _getenv_h(const char *name) {
    if (name && strcmp(name, "DYLD_INSERT_LIBRARIES") == 0) return NULL;
    return orig_getenv(name);
}
static int _uname_h(struct utsname *buf) {
    int ret = orig_uname(buf);
    if (ret == 0 && buf) {
        strlcpy(buf->machine, "iPhone15,3", sizeof(buf->machine));
        strlcpy(buf->release, "22.4.0", sizeof(buf->release));
    }
    return ret;
}

// واجهة منبثقة
static void showStageAlert(NSString *title, NSString *message) {
    dispatch_async(dispatch_get_main_queue(), ^{
        UIWindow *alertWindow = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
        alertWindow.windowLevel = UIWindowLevelAlert + 1;
        alertWindow.backgroundColor = [UIColor clearColor];
        alertWindow.rootViewController = [[UIViewController alloc] init];
        alertWindow.rootViewController.view.backgroundColor = [UIColor clearColor];
        [alertWindow makeKeyAndVisible];

        UIAlertController *alert = [UIAlertController
            alertControllerWithTitle:title
            message:message
            preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"موافق" style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
            alertWindow.hidden = YES;
        }]];
        [alertWindow.rootViewController presentViewController:alert animated:YES completion:nil];
    });
}

__attribute__((constructor))
static void _init() {
    @autoreleasepool {
        // Stage 0: تأكيد تحميل المكتبة
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
            showStageAlert(@"✅ المرحلة 0", @"تم تحميل المكتبة بنجاح");

            // Stage 1: fishhook getenv
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 1 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
                struct rebinding r1 = {"getenv", _getenv_h, (void**)&orig_getenv};
                rebind_symbols(&r1, 1);
                showStageAlert(@"✅ المرحلة 1", @"تم ربط getenv");

                // Stage 2: fishhook sysctl
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 0.5 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
                    struct rebinding r2 = {"sysctl", _sysctl_h, (void**)&orig_sysctl};
                    rebind_symbols(&r2, 1);
                    showStageAlert(@"✅ المرحلة 2", @"تم ربط sysctl");

                    // Stage 3: fishhook sysctlbyname
                    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 0.5 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
                        struct rebinding r3 = {"sysctlbyname", _sysctlbyname_h, (void**)&orig_sysctlbyname};
                        rebind_symbols(&r3, 1);
                        showStageAlert(@"✅ المرحلة 3", @"تم ربط sysctlbyname");

                        // Stage 4: fishhook uname
                        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 0.5 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
                            struct rebinding r4 = {"uname", _uname_h, (void**)&orig_uname};
                            rebind_symbols(&r4, 1);
                            showStageAlert(@"✅ المرحلة 4", @"تم ربط uname - كل شيء يعمل!");
                        });
                    });
                });
            });
        });
    }
}
