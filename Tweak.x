#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <sys/sysctl.h>
#import <sys/utsname.h>
#import <dlfcn.h>
#import <objc/runtime.h>
#import <mach/mach.h>
#import "fishhook.h"
#import <CommonCrypto/CommonHMAC.h>
#import <CommonCrypto/CommonDigest.h>
#include <time.h>
#include <stdlib.h>

extern int ptrace(int request, pid_t pid, caddr_t addr, int data);
extern const char* _dyld_get_image_name(uint32_t idx);
extern const struct mach_header* _dyld_get_image_header(uint32_t idx);

static int (*orig_sysctl)(int *, u_int, void *, size_t *, void *, size_t);
static int (*orig_sysctlbyname)(const char *, void *, size_t *, void *, size_t);
static int (*orig_ptrace)(int, pid_t, caddr_t, int);
static char* (*orig_getenv)(const char *);
static int (*orig_uname)(struct utsname *);
static const char* (*orig_dyld_name)(uint32_t);
static const struct mach_header* (*orig_dyld_header)(uint32_t);
static kern_return_t (*orig_vm_region)(mach_port_t, vm_address_t *, vm_size_t *, natural_t *, vm_region_recurse_info_t, mach_msg_type_number_t *);

// ==================== مراحل التشخيص ====================
__attribute__((constructor))
static void _init() {
    @autoreleasepool {
        NSLog(@"[ANOGS-DIAG] ✅ Stage 0: Library loaded successfully!");

        // المرحلة 1: اختبر بصمة بدون أي hooks
        NSLog(@"[ANOGS-DIAG] 🔍 Stage 1: Generating fingerprint...");
        NSString *fp = @"test";
        @try {
            fp = _generateFingerprint(); // استدعاء عادي
            NSLog(@"[ANOGS-DIAG] ✅ Stage 1 PASS: %@", fp);
        } @catch (NSException *e) {
            NSLog(@"[ANOGS-DIAG] ❌ Stage 1 FAIL: %@", e);
            return;
        }

        // المرحلة 2: واجهة المستخدم بدون hooks
        NSLog(@"[ANOGS-DIAG] 🔍 Stage 2: Showing alert (no hooks)...");
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 2.0 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
            @try {
                UIWindow *alertWindow = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
                alertWindow.windowLevel = UIWindowLevelAlert + 1;
                alertWindow.backgroundColor = [UIColor clearColor];
                alertWindow.rootViewController = [[UIViewController alloc] init];
                alertWindow.rootViewController.view.backgroundColor = [UIColor clearColor];
                [alertWindow makeKeyAndVisible];
                UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"DIAG" message:@"Stage 2 OK" preferredStyle:UIAlertControllerStyleAlert];
                [alert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
                [alertWindow.rootViewController presentViewController:alert animated:YES completion:nil];
                NSLog(@"[ANOGS-DIAG] ✅ Stage 2 PASS");
            } @catch (NSException *e) {
                NSLog(@"[ANOGS-DIAG] ❌ Stage 2 FAIL: %@", e);
            }
        });

        // المرحلة 3: اختبر fishhook لدالة واحدة فقط (sysctl)
        NSLog(@"[ANOGS-DIAG] 🔍 Stage 3: fishhook sysctl only...");
        static int _sysctl_h(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
            if (namelen >= 2 && name[0] == CTL_KERN && name[1] == KERN_PROC) return -1;
            return orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen);
        }
        struct rebinding sysctl_rb = {"sysctl", _sysctl_h, (void**)&orig_sysctl};
        rebind_symbols(&sysctl_rb, 1);
        NSLog(@"[ANOGS-DIAG] ✅ Stage 3 PASS (sysctl hooked)");
    }
}

static NSString* _generateFingerprint() {
    // نسخة مبسطة جداً للتشخيص
    return @"DIAG-FP";
}
