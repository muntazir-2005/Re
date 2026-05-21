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

// ==================== تصريح يدوي للدوال المخفية ====================
extern int ptrace(int request, pid_t pid, caddr_t addr, int data);
extern const char* _dyld_get_image_name(uint32_t idx);
extern const struct mach_header* _dyld_get_image_header(uint32_t idx);

// ==================== مؤشرات الدوال الأصلية ====================
static int (*orig_sysctl)(int *, u_int, void *, size_t *, void *, size_t);
static int (*orig_sysctlbyname)(const char *, void *, size_t *, void *, size_t);
static int (*orig_ptrace)(int, pid_t, caddr_t, int);
static char* (*orig_getenv)(const char *);
static int (*orig_uname)(struct utsname *);
static const char* (*orig_dyld_name)(uint32_t);
static const struct mach_header* (*orig_dyld_header)(uint32_t);
static kern_return_t (*orig_vm_region)(mach_port_t, vm_address_t *, vm_size_t *, natural_t *, vm_region_recurse_info_t, mach_msg_type_number_t *);

// ==================== بدائل الحماية ====================
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

static const char* _dyld_name_h(uint32_t idx) {
    const char *n = orig_dyld_name(idx);
    if (n && strstr(n, "ANOGS.dylib")) return "";
    return n;
}

static const struct mach_header* _dyld_header_h(uint32_t idx) {
    const char *n = orig_dyld_name(idx);
    if (n && strstr(n, "ANOGS.dylib")) return NULL;
    return orig_dyld_header(idx);
}

static kern_return_t _vm_region_h(mach_port_t target, vm_address_t *addr, vm_size_t *size, natural_t *depth, vm_region_recurse_info_t info, mach_msg_type_number_t *infoCnt) {
    kern_return_t ret = orig_vm_region(target, addr, size, depth, info, infoCnt);
    if (ret == KERN_SUCCESS && infoCnt && *infoCnt >= sizeof(vm_region_submap_info_data_64_t)) {
        vm_region_submap_info_data_64_t *submap = (vm_region_submap_info_data_64_t *)info;
        submap->protection = VM_PROT_READ | VM_PROT_EXECUTE;
    }
    return ret;
}

// ==================== بصمة AI ====================
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

// ==================== Swizzling خصائص الجهاز ====================
static NSOperatingSystemVersion _osVer_h(id self, SEL _cmd) {
    return (NSOperatingSystemVersion){17, 4, 1};
}
static NSString* _model_h(id self, SEL _cmd) { return @"iPhone15,3"; }
static NSUUID* _idfv_h(id self, SEL _cmd) {
    return [[NSUUID alloc] initWithUUIDString:@"E621E1F8-C36C-495A-93FC-0C247A3E6E5F"];
}
static BOOL _fileExists_h(id self, SEL _cmd, NSString *path) {
    NSArray *bad = @[@"frida", @"cycript", @"substrate", @"Cydia", @"Sileo", @"gdb", @"lldb"];
    for (NSString *w in bad)
        if ([path rangeOfString:w options:NSCaseInsensitiveSearch].location != NSNotFound)
            return NO;
    BOOL (*orig)(id, SEL, NSString*) = (BOOL (*)(id, SEL, NSString*))class_getMethodImplementation([NSFileManager class], @selector(fileExistsAtPath:));
    return orig(self, _cmd, path);
}

// ==================== اعتراض الشبكة ====================
static void (*orig_setValueHTTP)(id, SEL, NSString*, NSString*);
static void _setValueHTTP_h(id self, SEL _cmd, NSString *val, NSString *field) {
    if ([field isEqualToString:@"X-AI-Fingerprint"])
        val = _currentFP;
    orig_setValueHTTP(self, _cmd, val, field);
}

// ==================== واجهة التأكيد ====================
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

// ==================== التهيئة ====================
__attribute__((constructor))
static void _init() {
    @autoreleasepool {
        struct rebinding reb[] = {
            {"sysctl", _sysctl_h, (void**)&orig_sysctl},
            {"sysctlbyname", _sysctlbyname_h, (void**)&orig_sysctlbyname},
            {"ptrace", _ptrace_h, (void**)&orig_ptrace},
            {"getenv", _getenv_h, (void**)&orig_getenv},
            {"uname", _uname_h, (void**)&orig_uname},
            {"_dyld_get_image_name", _dyld_name_h, (void**)&orig_dyld_name},
            {"_dyld_get_image_header", _dyld_header_h, (void**)&orig_dyld_header},
            {"vm_region_recurse_64", _vm_region_h, (void**)&orig_vm_region}
        };
        rebind_symbols(reb, sizeof(reb)/sizeof(reb[0]));

        class_replaceMethod(objc_getClass("NSProcessInfo"), @selector(operatingSystemVersion), (IMP)_osVer_h, "@@:");
        class_replaceMethod(objc_getClass("UIDevice"), @selector(model), (IMP)_model_h, "@@:");
        class_replaceMethod(objc_getClass("UIDevice"), @selector(identifierForVendor), (IMP)_idfv_h, "@@:");
        class_replaceMethod(objc_getClass("NSFileManager"), @selector(fileExistsAtPath:), (IMP)_fileExists_h, "B@:@");

        Method m = class_getInstanceMethod(objc_getClass("NSMutableURLRequest"), @selector(setValue:forHTTPHeaderField:));
        if (m) {
            orig_setValueHTTP = (void*)method_getImplementation(m);
            method_setImplementation(m, (IMP)_setValueHTTP_h);
        }

        _currentFP = _generateFingerprint();
        NSLog(@"[ANOGS-AI] ✅ جميع الحمايات نشطة | البصمة: %@", _currentFP);
        _showAlert();
    }
}
