#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <sys/sysctl.h>
#import <sys/utsname.h>
#import <dlfcn.h>
#import <objc/runtime.h>
#import <mach/mach.h>
#import <CommonCrypto/CommonHMAC.h>
#import <CommonCrypto/CommonDigest.h>
#include <time.h>
#include <stdlib.h>

// ==================== تصريح يدوي ====================
extern int ptrace(int request, pid_t pid, caddr_t addr, int data);
extern const char* _dyld_get_image_name(uint32_t idx);
extern const struct mach_header* _dyld_get_image_header(uint32_t idx);

// ==================== DYLD_INTERPOSE الآمن (لا يلمس الذاكرة) ====================
#define DYLD_INTERPOSE(_replacement, _replacee) \
    __attribute__((used)) static struct { \
        const void *replacement; \
        const void *replacee; \
    } _interpose_##_replacee __attribute__((section("__DATA,__interpose"))) = { \
        (const void *)(unsigned long)&_replacement, \
        (const void *)(unsigned long)&_replacee \
    };

// ==================== دوال الحماية باستخدام dlsym في كل مرة ====================
static int _sysctl_h(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    static int (*real_sysctl)(int *, u_int, void *, size_t *, void *, size_t) = NULL;
    if (!real_sysctl) real_sysctl = dlsym(RTLD_NEXT, "sysctl");
    if (namelen >= 2 && name[0] == CTL_KERN && name[1] == KERN_PROC) return -1;
    return real_sysctl(name, namelen, oldp, oldlenp, newp, newlen);
}
DYLD_INTERPOSE(_sysctl_h, sysctl);

static int _sysctlbyname_h(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    static int (*real_sysctlbyname)(const char *, void *, size_t *, void *, size_t) = NULL;
    if (!real_sysctlbyname) real_sysctlbyname = dlsym(RTLD_NEXT, "sysctlbyname");
    if (name && strstr(name, "proc")) return -1;
    return real_sysctlbyname(name, oldp, oldlenp, newp, newlen);
}
DYLD_INTERPOSE(_sysctlbyname_h, sysctlbyname);

static int _ptrace_h(int request, pid_t pid, caddr_t addr, int data) {
    static int (*real_ptrace)(int, pid_t, caddr_t, int) = NULL;
    if (!real_ptrace) real_ptrace = dlsym(RTLD_NEXT, "ptrace");
    if (request == 31) return 0; // PT_DENY_ATTACH
    return real_ptrace(request, pid, addr, data);
}
DYLD_INTERPOSE(_ptrace_h, ptrace);

static char* _getenv_h(const char *name) {
    static char* (*real_getenv)(const char *) = NULL;
    if (!real_getenv) real_getenv = dlsym(RTLD_NEXT, "getenv");
    if (name && strcmp(name, "DYLD_INSERT_LIBRARIES") == 0) return NULL;
    return real_getenv(name);
}
DYLD_INTERPOSE(_getenv_h, getenv);

static int _uname_h(struct utsname *buf) {
    static int (*real_uname)(struct utsname *) = NULL;
    if (!real_uname) real_uname = dlsym(RTLD_NEXT, "uname");
    int ret = real_uname(buf);
    if (ret == 0 && buf) {
        strlcpy(buf->machine, "iPhone15,3", sizeof(buf->machine));
        strlcpy(buf->release, "22.4.0", sizeof(buf->release));
    }
    return ret;
}
DYLD_INTERPOSE(_uname_h, uname);

static const char* _dyld_name_h(uint32_t idx) {
    static const char* (*real)(uint32_t) = NULL;
    if (!real) real = dlsym(RTLD_DEFAULT, "_dyld_get_image_name");
    const char *n = real(idx);
    if (n && strstr(n, "ANOGS.dylib")) return "";
    return n;
}
DYLD_INTERPOSE(_dyld_name_h, _dyld_get_image_name);

static const struct mach_header* _dyld_header_h(uint32_t idx) {
    static const struct mach_header* (*real)(uint32_t) = NULL;
    if (!real) real = dlsym(RTLD_DEFAULT, "_dyld_get_image_header");
    const char *n = _dyld_get_image_name(idx); // استدعاء النسخة البديلة
    if (n && strstr(n, "ANOGS.dylib")) return NULL;
    return real(idx);
}
DYLD_INTERPOSE(_dyld_header_h, _dyld_get_image_header);

static kern_return_t _vm_region_h(mach_port_t target, vm_address_t *addr, vm_size_t *size, natural_t *depth, vm_region_recurse_info_t info, mach_msg_type_number_t *infoCnt) {
    static kern_return_t (*real)(mach_port_t, vm_address_t *, vm_size_t *, natural_t *, vm_region_recurse_info_t, mach_msg_type_number_t *) = NULL;
    if (!real) real = dlsym(RTLD_DEFAULT, "vm_region_recurse_64");
    kern_return_t ret = real(target, addr, size, depth, info, infoCnt);
    if (ret == KERN_SUCCESS && infoCnt && *infoCnt >= sizeof(vm_region_submap_info_data_64_t)) {
        vm_region_submap_info_data_64_t *submap = (vm_region_submap_info_data_64_t *)info;
        submap->protection = VM_PROT_READ | VM_PROT_EXECUTE;
    }
    return ret;
}
DYLD_INTERPOSE(_vm_region_h, vm_region_recurse_64);

// ==================== Swizzling (استمرار بنفس الطريقة لأنها لا تلمس GOT) ====================
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
static void (*orig_setValueHTTP)(id, SEL, NSString*, NSString*);
static void _setValueHTTP_h(id self, SEL _cmd, NSString *val, NSString *field) {
    if ([field isEqualToString:@"X-AI-Fingerprint"])
        val = _currentFP;
    orig_setValueHTTP(self, _cmd, val, field);
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
static NSString* _generateFingerprint() { /* نفس ما لديك */ }
static NSString *_currentFP = nil;

// ==================== واجهة التأكيد ====================
static void _showAlert() { /* نفس ما لديك */ }

// ==================== التهيئة ====================
__attribute__((constructor))
static void _init() {
    @autoreleasepool {
        // تثبيت Swizzling فقط (لا fishhook)
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
        NSLog(@"[ANOGS-AI] ✅ جميع الحمايات نشطة (No-Memory-Touch) | البصمة: %@", _currentFP);
        _showAlert();
    }
}
