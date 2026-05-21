#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import "fishhook.h"
#import <sys/sysctl.h>
#import <sys/utsname.h>
#import <dlfcn.h>
#import <objc/runtime.h>
#import <CommonCrypto/CommonHMAC.h>
#import <CommonCrypto/CommonDigest.h>
#include <time.h>
#include <stdlib.h>

extern int ptrace(int request, pid_t pid, caddr_t addr, int data);

// ========== المؤشرات الأصلية ==========
static int (*orig_sysctl)(int *, u_int, void *, size_t *, void *, size_t);
static int (*orig_sysctlbyname)(const char *, void *, size_t *, void *, size_t);
static int (*orig_ptrace)(int, pid_t, caddr_t, int);
static char* (*orig_getenv)(const char *);
static int (*orig_uname)(struct utsname *);

// ========== دوال الحماية ==========
static int _sysctl_h(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    if (namelen >= 2 && name[0] == CTL_KERN && name[1] == KERN_PROC) return -1;
    return orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen);
}
static int _sysctlbyname_h(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    if (name && strstr(name, "proc")) return -1;
    return orig_sysctlbyname(name, oldp, oldlenp, newp, newlen);
}
#define PT_DENY_ATTACH 31
static int _ptrace_h(int request, pid_t pid, caddr_t addr, int data) {
    if (request == PT_DENY_ATTACH) return 0;
    return orig_ptrace(request, pid, addr, data);
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

// ========== Swizzling لإخفاء الملفات (آمن بعد UIKit) ==========
static BOOL (*orig_fileExists)(id, SEL, NSString*);
static BOOL _fileExists_h(id self, SEL _cmd, NSString *path) {
    NSArray *bad = @[@"frida", @"cycript", @"substrate", @"Cydia", @"Sileo", @"gdb", @"lldb"];
    for (NSString *w in bad) {
        if ([path rangeOfString:w options:NSCaseInsensitiveSearch].location != NSNotFound)
            return NO;
    }
    return orig_fileExists(self, _cmd, path);
}

// ========== بصمة AI ==========
static NSString* _hmac(NSString *msg, NSString *key) {
    unsigned char hmac[CC_SHA256_DIGEST_LENGTH];
    CCHmac(kCCHmacAlgSHA256, [key UTF8String], [key length],
           [msg UTF8String], [msg length], hmac);
    NSMutableString *r = [NSMutableString stringWithCapacity:64];
    for (int i=0; i<CC_SHA256_DIGEST_LENGTH; i++) [r appendFormat:@"%02x", hmac[i]];
    return r;
}
static NSString* _generateFingerprint() {
    @autoreleasepool {
        static NSString *sessUUID = nil;
        static dispatch_once_t once;
        dispatch_once(&once, ^{ sessUUID = [[NSUUID UUID] UUIDString]; });
        NSTimeInterval ts = [[NSDate date] timeIntervalSince1970];
        NSString *micro = [NSString stringWithFormat:@"%.0f", ts * 1000];
        int magic = 106 + arc4random_uniform(999894);
        NSString *realIDFV = [[[UIDevice currentDevice] identifierForVendor] UUIDString];
        NSString *salt = [NSString stringWithFormat:@"ANOGS_SALT_%d", magic];
        NSString *maskedIDFV = _hmac(realIDFV, salt);
        NSString *bundleID = [[NSBundle mainBundle] bundleIdentifier] ?: @"com.unknown";
        NSString *maskedBundle = _hmac(bundleID, salt);
        NSString *raw = [NSString stringWithFormat:@"%@|%@|%@|%@|%d|726", maskedIDFV, maskedBundle, sessUUID, micro, magic];
        return [_hmac(raw, sessUUID) substringToIndex:64];
    }
}
static NSString *_currentFP = nil;

// ========== اعتراض الشبكة ==========
static void (*orig_setValueHTTP)(id, SEL, NSString*, NSString*);
static void _setValueHTTP_h(id self, SEL _cmd, NSString *val, NSString *field) {
    if ([field isEqualToString:@"X-AI-Fingerprint"])
        val = _currentFP;
    orig_setValueHTTP(self, _cmd, val, field);
}

// ========== واجهة التأكيد ==========
static void _showAlert() {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 2.0 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
        UIWindow *alertWindow = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
        alertWindow.windowLevel = UIWindowLevelAlert + 1;
        alertWindow.backgroundColor = [UIColor clearColor];
        alertWindow.rootViewController = [[UIViewController alloc] init];
        alertWindow.rootViewController.view.backgroundColor = [UIColor clearColor];
        [alertWindow makeKeyAndVisible];

        UIAlertController *alert = [UIAlertController
            alertControllerWithTitle:@"🔐 ANOGS-AI"
            message:[NSString stringWithFormat:@"✅ تم التجاوز بنجاح\nالبصمة: %@", _currentFP]
            preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"موافق" style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
            alertWindow.hidden = YES;
        }]];
        [alertWindow.rootViewController presentViewController:alert animated:YES completion:nil];
    });
}

// ========== التهيئة ==========
__attribute__((constructor))
static void _init() {
    @autoreleasepool {
        // ربط دوال C
        struct rebinding reb[] = {
            {"getenv", _getenv_h, (void**)&orig_getenv},
            {"sysctl", _sysctl_h, (void**)&orig_sysctl},
            {"sysctlbyname", _sysctlbyname_h, (void**)&orig_sysctlbyname},
            {"ptrace", _ptrace_h, (void**)&orig_ptrace},
            {"uname", _uname_h, (void**)&orig_uname},
        };
        rebind_symbols(reb, sizeof(reb)/sizeof(reb[0]));

        // ربط Swizzling بعد تحميل UIKit (تأخير)
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 1.0 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
            Class fileMgr = objc_getClass("NSFileManager");
            Method m = class_getInstanceMethod(fileMgr, @selector(fileExistsAtPath:));
            if (m) {
                orig_fileExists = (void*)method_getImplementation(m);
                method_setImplementation(m, (IMP)_fileExists_h);
            }
        });

        // اعتراض الشبكة
        Method m = class_getInstanceMethod(objc_getClass("NSMutableURLRequest"), @selector(setValue:forHTTPHeaderField:));
        if (m) {
            orig_setValueHTTP = (void*)method_getImplementation(m);
            method_setImplementation(m, (IMP)_setValueHTTP_h);
        }

        _currentFP = _generateFingerprint();
        NSLog(@"[ANOGS-AI] ✅ جميع الحمايات الآمنة نشطة | البصمة: %@", _currentFP);
        _showAlert();
    }
}
