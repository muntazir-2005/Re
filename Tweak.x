#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <Security/Security.h>
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

// ==================== تشفير السلاسل ====================
static NSString* _ds(unsigned char *enc, int len, unsigned char key) {
    unsigned char *dec = malloc(len + 1);
    for (int i = 0; i < len; i++) dec[i] = enc[i] ^ key;
    dec[len] = 0;
    NSString *str = [NSString stringWithUTF8String:(const char *)dec];
    free(dec);
    return str;
}

// ==================== 1. sysctl ====================
static int (*orig_sysctl)(int *, u_int, void *, size_t *, void *, size_t);
static int _sysctl_h(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    if (namelen >= 2 && name[0] == CTL_KERN && name[1] == KERN_PROC) return -1;
    return orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen);
}

// ==================== 2. sysctlbyname ====================
static int (*orig_sysctlbyname)(const char *, void *, size_t *, void *, size_t);
static int _sysctlbyname_h(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    NSString *procWord = _ds((unsigned char[]){0x76,0x73,0x76,0x70}, 4, 0x05);
    if (name && strstr(name, [procWord UTF8String])) return -1;
    return orig_sysctlbyname(name, oldp, oldlenp, newp, newlen);
}

// ==================== 3. ptrace ====================
#define PT_DENY_ATTACH 31
static int (*orig_ptrace)(int, pid_t, caddr_t, int);
static int _ptrace_h(int request, pid_t pid, caddr_t addr, int data) {
    if (request == PT_DENY_ATTACH) return 0;
    return orig_ptrace(request, pid, addr, data);
}

// ==================== 4. getenv ====================
static char* (*orig_getenv)(const char *);
static char* _getenv_h(const char *name) {
    NSString *libInsert = _ds((unsigned char[]){0x25,0x2E,0x26,0x2B,0x5F,0x2C,0x28,0x2A,0x23,0x2A,0x5F,0x26,0x2C,0x29,0x23,0x2E,0x23,0x2A,0x2A,0x2C}, 20, 0x55);
    if (name && strcmp(name, [libInsert UTF8String]) == 0) return NULL;
    return orig_getenv(name);
}

// ==================== 5. uname ====================
static int (*orig_uname)(struct utsname *);
static int _uname_h(struct utsname *buf) {
    int ret = orig_uname(buf);
    if (ret == 0 && buf) {
        NSString *machineModel = _ds((unsigned char[]){0x2D,0x2A,0x27,0x28,0x28,0x2A,0x2F,0x25,0x22,0x28}, 10, 0x55);
        strlcpy(buf->machine, [machineModel UTF8String], sizeof(buf->machine));
        NSString *releaseVer = _ds((unsigned char[]){0x2F,0x2F,0x27,0x27,0x2F}, 5, 0x55);
        strlcpy(buf->release, [releaseVer UTF8String], sizeof(buf->release));
    }
    return ret;
}

// ==================== 6. dyld hooks ====================
static const char* (*orig_dyld_name)(uint32_t);
static const struct mach_header* (*orig_dyld_header)(uint32_t);
static const char* _dyld_name_h(uint32_t idx) {
    const char *n = orig_dyld_name(idx);
    NSString *libName = _ds((unsigned char[]){0x2E,0x28,0x28,0x2A,0x2F,0x26,0x2B,0x2A,0x25,0x2E}, 10, 0x55);
    if (n && strstr(n, [libName UTF8String])) return "";
    return n;
}
static const struct mach_header* _dyld_header_h(uint32_t idx) {
    const char *n = orig_dyld_name(idx);
    NSString *libName = _ds((unsigned char[]){0x2E,0x28,0x28,0x2A,0x2F,0x26,0x2B,0x2A,0x25,0x2E}, 10, 0x55);
    if (n && strstr(n, [libName UTF8String])) return NULL;
    return orig_dyld_header(idx);
}

// ==================== 7. vm_region_recurse_64 ====================
static kern_return_t (*orig_vm_region)(mach_port_t, vm_address_t *, vm_size_t *, natural_t *, vm_region_recurse_info_t, mach_msg_type_number_t *);
static kern_return_t _vm_region_h(mach_port_t target, vm_address_t *addr, vm_size_t *size, natural_t *depth, vm_region_recurse_info_t info, mach_msg_type_number_t *infoCnt) {
    kern_return_t ret = orig_vm_region(target, addr, size, depth, info, infoCnt);
    if (ret == KERN_SUCCESS && infoCnt && *infoCnt >= sizeof(vm_region_submap_info_data_64_t)) {
        vm_region_submap_info_data_64_t *submap = (vm_region_submap_info_data_64_t *)info;
        submap->protection = VM_PROT_READ | VM_PROT_EXECUTE;
    }
    return ret;
}

// ==================== دوال البصمة ====================
static NSString* _hmac_sha256(NSString *msg, NSString *key) {
    const char *ckey = [key UTF8String], *cdata = [msg UTF8String];
    unsigned char hmac[CC_SHA256_DIGEST_LENGTH];
    CCHmac(kCCHmacAlgSHA256, ckey, strlen(ckey), cdata, strlen(cdata), hmac);
    NSMutableString *res = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) [res appendFormat:@"%02x", hmac[i]];
    return res;
}

static NSString* _generateFingerprint() {
    @autoreleasepool {
        NSTimeInterval ts = [[NSDate date] timeIntervalSince1970];
        NSString *micro = [NSString stringWithFormat:@"%.0f", ts * 1000];

        static NSString *sessUUID = nil;
        static dispatch_once_t once;
        dispatch_once(&once, ^{ sessUUID = [[NSUUID UUID] UUIDString]; });

        int magic = 106 + arc4random_uniform(999894);
        NSString *code = [NSString stringWithFormat:@"%d", magic];

        NSString *realIDFV = [[[UIDevice currentDevice] identifierForVendor] UUIDString];
        NSString *salt = _ds((unsigned char[]){0x0E,0x13,0x1A,0x1C,0x1F,0x15,0x0F,0x15,0x1A,0x1B,0x12,0x0F,0x0C,0x1F,0x10,0x0A}, 16, 0x72);
        NSString *maskedIDFV = _hmac_sha256(realIDFV, salt);
        NSString *bundleID = [[NSBundle mainBundle] bundleIdentifier] ?: @"com.unknown";
        NSString *maskedBundle = _hmac_sha256(bundleID, salt);

        NSString *raw = [NSString stringWithFormat:@"%@|%@|%@|%@|%@|726",
                         maskedIDFV, maskedBundle, sessUUID, micro, code];
        NSString *final = _hmac_sha256(raw, sessUUID);
        return [final substringToIndex:64];
    }
}

static NSString *_currentFP = nil;

// ==================== Swizzling Objective-C ====================
static NSOperatingSystemVersion _osVer_h(id self, SEL _cmd) {
    return (NSOperatingSystemVersion){17, 4, 1};
}
static NSString* _model_h(id self, SEL _cmd) { return @"iPhone15,3"; }
static NSUUID* _idfv_h(id self, SEL _cmd) {
    return [[NSUUID alloc] initWithUUIDString:@"E621E1F8-C36C-495A-93FC-0C247A3E6E5F"];
}
static BOOL _fileExists_h(id self, SEL _cmd, NSString *path) {
    NSArray *bad = @[
        _ds((unsigned char[]){0x27,0x23,0x26,0x2B,0x2E}, 5, 0x55),
        _ds((unsigned char[]){0x32,0x24,0x26,0x22,0x24,0x23,0x2C}, 7, 0x55)
    ];
    for (NSString *w in bad) {
        if ([path rangeOfString:w options:NSCaseInsensitiveSearch].location != NSNotFound)
            return NO;
    }
    BOOL (*orig)(id, SEL, NSString*) = (BOOL (*)(id, SEL, NSString*))class_getMethodImplementation([NSFileManager class], @selector(fileExistsAtPath:));
    return orig(self, _cmd, path);
}

// اعتراض الشبكة
static void (*orig_setValue)(id, SEL, NSString*, NSString*);
static void _setValue_h(id self, SEL _cmd, NSString *val, NSString *field) {
    NSString *header = _ds((unsigned char[]){0x41,0x56,0x45,0x55,0x5A,0x42,0x45,0x5F,0x57,0x48,0x42,0x44,0x5F,0x55,0x46,0x47}, 16, 0x33);
    if ([field isEqualToString:header]) val = _currentFP;
    orig_setValue(self, _cmd, val, field);
}

// ==================== واجهة حديثة (نافذة مستقلة) ====================
static void _showModernAlert() {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 2.0 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
        UIWindow *alertWindow = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
        alertWindow.windowLevel = UIWindowLevelAlert + 1;
        alertWindow.backgroundColor = [UIColor clearColor];
        alertWindow.rootViewController = [[UIViewController alloc] init];
        alertWindow.rootViewController.view.backgroundColor = [UIColor clearColor];
        [alertWindow makeKeyAndVisible];

        UIAlertController *alert = [UIAlertController
            alertControllerWithTitle:@"🔐 ANOGS"
            message:[NSString stringWithFormat:@"✅ تم التجاوز بنجاح\nالبصمة: %@", _currentFP]
            preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"موافق" style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
            alertWindow.hidden = YES;
        }]];
        [alertWindow.rootViewController presentViewController:alert animated:YES completion:nil];
    });
}

// ==================== التهيئة (fishhook) ====================
__attribute__((constructor))
static void _init() {
    @autoreleasepool {
        // fishhook - آمن ولا يسبب deadlock
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

        // Swizzling Objective-C
        class_replaceMethod(objc_getClass("NSProcessInfo"), @selector(operatingSystemVersion), (IMP)_osVer_h, "@@:");
        class_replaceMethod(objc_getClass("UIDevice"), @selector(model), (IMP)_model_h, "@@:");
        class_replaceMethod(objc_getClass("UIDevice"), @selector(identifierForVendor), (IMP)_idfv_h, "@@:");
        class_replaceMethod(objc_getClass("NSFileManager"), @selector(fileExistsAtPath:), (IMP)_fileExists_h, "B@:@");

        Class req = objc_getClass("NSMutableURLRequest");
        Method m = class_getInstanceMethod(req, @selector(setValue:forHTTPHeaderField:));
        if (m) {
            orig_setValue = (void*)method_getImplementation(m);
            method_setImplementation(m, (IMP)_setValue_h);
        }

        _currentFP = _generateFingerprint();
        NSLog(@"[ANOGS] ✅ All protections active | FP: %@", _currentFP);

        _showModernAlert();
    }
}
