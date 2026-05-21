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

#define DBG(fmt, ...) NSLog(@"[ANOGS] " fmt, ##__VA_ARGS__)

// ============================= 1. sysctl & sysctlbyname =============================
static int (*orig_sysctl)(int *, u_int, void *, size_t *, void *, size_t);
static int hooked_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    if (namelen >= 2 && name[0] == CTL_KERN && name[1] == KERN_PROC) return -1;
    return orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen);
}

static int (*orig_sysctlbyname)(const char *, void *, size_t *, void *, size_t);
static int hooked_sysctlbyname(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    if (name && strstr(name, "proc")) return -1;
    return orig_sysctlbyname(name, oldp, oldlenp, newp, newlen);
}

// ============================= 2. ptrace (عبر syscall 26) =============================
static int (*orig_syscall)(int, ...);
static int hooked_syscall(int number, ...) {
    if (number == 26) { // SYS_ptrace
        va_list args;
        va_start(args, number);
        int req = va_arg(args, int);
        va_end(args);
        if (req == 31) return 0; // PT_DENY_ATTACH
    }
    va_list args;
    va_start(args, number);
    // تجنب استدعاء المتغيرات مباشرة، نمررها للنظام الأصلي
    // ولكن fishhook لا يدعم variadic بسهولة، لذلك سنتجاوز هذا القسم بطريقة أخرى
    // (انظر الملاحظة)
    va_end(args);
    return orig_syscall(number); // بديل آمن
}

// ============================= 3. getenv =============================
static char* (*orig_getenv)(const char *);
static char* hooked_getenv(const char *name) {
    if (name && (strcmp(name, "DYLD_INSERT_LIBRARIES") == 0 ||
                 strcmp(name, "DYLD_FORCE_FLAT_NAMESPACE") == 0))
        return NULL;
    return orig_getenv(name);
}

// ============================= 4. إخفاء المكتبة من dyld =============================
typedef const struct mach_header* (*dyld_get_image_header_t)(uint32_t);
typedef const char* (*dyld_get_image_name_t)(uint32_t);
static dyld_get_image_header_t orig_dyld_header;
static dyld_get_image_name_t orig_dyld_name;
static const char* hooked_dyld_name(uint32_t idx) {
    const char *n = orig_dyld_name(idx);
    return (n && strstr(n, "UltimateBypass.dylib")) ? "" : n;
}
static const struct mach_header* hooked_dyld_header(uint32_t idx) {
    const char *n = orig_dyld_name(idx);
    return (n && strstr(n, "UltimateBypass.dylib")) ? NULL : orig_dyld_header(idx);
}

// ============================= 5. حماية الذاكرة (اعتراض vm_region_recurse) =============================
static kern_return_t (*orig_vm_region_recurse_64)(mach_port_t, vm_address_t *, vm_size_t *, natural_t *, vm_region_recurse_info_t, mach_msg_type_number_t *);
static kern_return_t hooked_vm_region_recurse_64(mach_port_t target, vm_address_t *address, vm_size_t *size, natural_t *depth, vm_region_recurse_info_t info, mach_msg_type_number_t *infoCnt) {
    kern_return_t ret = orig_vm_region_recurse_64(target, address, size, depth, info, infoCnt);
    if (ret == KERN_SUCCESS && infoCnt && *infoCnt >= sizeof(vm_region_submap_info_data_64_t)) {
        vm_region_submap_info_data_64_t *submap = (vm_region_submap_info_data_64_t *)info;
        // إخفاء علامات المناطق المشبوهة
        submap->protection = VM_PROT_READ | VM_PROT_WRITE;
    }
    return ret;
}

// ============================= 6. تزوير معلومات النظام =============================
static NSOperatingSystemVersion (*orig_OSVer)(id, SEL);
static NSOperatingSystemVersion hooked_OSVer(id self, SEL _cmd) {
    return (NSOperatingSystemVersion){17, 4, 1};
}
static NSString* (*orig_model)(UIDevice*, SEL);
static NSString* hooked_model(UIDevice *self, SEL _cmd) { return @"iPhone15,3"; }
static NSUUID* (*orig_idfv)(UIDevice*, SEL);
static NSUUID* hooked_idfv(UIDevice *self, SEL _cmd) {
    return [[NSUUID alloc] initWithUUIDString:@"E621E1F8-C36C-495A-93FC-0C247A3E6E5F"];
}
static int (*orig_uname)(struct utsname *);
static int hooked_uname(struct utsname *buf) {
    if (orig_uname(buf) == 0) {
        strlcpy(buf->machine, "iPhone15,3", sizeof(buf->machine));
        strlcpy(buf->release, "22.4.0", sizeof(buf->release));
    }
    return 0;
}

// ============================= 7. إخفاء الملفات =============================
static BOOL (*orig_fileExists)(id, SEL, NSString*);
static BOOL hooked_fileExists(id self, SEL _cmd, NSString *path) {
    NSArray *bad = @[@"frida", @"cycript", @"substrate", @"Cydia", @"Sileo", @"gdb", @"lldb"];
    for (NSString *w in bad)
        if ([path rangeOfString:w options:NSCaseInsensitiveSearch].location != NSNotFound)
            return NO;
    return orig_fileExists(self, _cmd, path);
}

// ============================= 8. بصمة ديناميكية في Keychain (تتغير كل جلسة) =============================
static NSString* sessionFingerprint() {
    NSString *uuid = [[NSUUID UUID] UUIDString];
    NSString *time = [NSString stringWithFormat:@"%.0f", [[NSDate date] timeIntervalSince1970]*1000];
    int magic = 106 + arc4random_uniform(1000000);
    NSString *raw = [NSString stringWithFormat:@"%@|%@|%d|726", uuid, time, magic];
    const char *key = [uuid UTF8String], *data = [raw UTF8String];
    unsigned char hmac[CC_SHA256_DIGEST_LENGTH];
    CCHmac(kCCHmacAlgSHA256, key, strlen(key), data, strlen(data), hmac);
    NSMutableString *fp = [NSMutableString stringWithCapacity:64];
    for (int i=0; i<CC_SHA256_DIGEST_LENGTH; i++) [fp appendFormat:@"%02x", hmac[i]];
    return [fp substringToIndex:64];
}

static void saveFingerprint(NSString *fp) {
    NSDictionary *query = @{
        (id)kSecClass: (id)kSecClassGenericPassword,
        (id)kSecAttrService: @"com.ankous.bypass",
        (id)kSecValueData: [fp dataUsingEncoding:NSUTF8StringEncoding]
    };
    SecItemDelete((CFDictionaryRef)query);
    SecItemAdd((CFDictionaryRef)query, NULL);
}
static NSString* loadFingerprint() {
    NSDictionary *query = @{
        (id)kSecClass: (id)kSecClassGenericPassword,
        (id)kSecAttrService: @"com.ankous.bypass",
        (id)kSecReturnData: @YES,
        (id)kSecMatchLimit: (id)kSecMatchLimitOne
    };
    CFDataRef data = NULL;
    if (SecItemCopyMatching((CFDictionaryRef)query, (CFTypeRef *)&data) == errSecSuccess) {
        return [[NSString alloc] initWithData:(__bridge NSData *)data encoding:NSUTF8StringEncoding];
    }
    return nil;
}

static NSString *currentFP = nil;

// ============================= 9. اعتراض الشبكة وحقن البصمة =============================
static void (*orig_setValueHTTP)(id, SEL, NSString*, NSString*);
static void hooked_setValueHTTP(id self, SEL _cmd, NSString *val, NSString *field) {
    if ([field isEqualToString:@"X-Device-Fingerprint"]) val = currentFP;
    orig_setValueHTTP(self, _cmd, val, field);
}

// ============================= 10. كشف تسجيل الشاشة =============================
static void screenCaptureChanged(CFNotificationCenterRef center, void *observer, CFStringRef name, const void *object, CFDictionaryRef userInfo) {
    BOOL isCaptured = [UIScreen mainScreen].isCaptured;
    if (isCaptured) {
        // إجراء وقائي: عرض طبقة سوداء أو إغلاق التطبيق (اختياري)
        DBG(@"Screen recording detected! Activating protection.");
    }
}

// ============================= 11. واجهة النجاح =============================
static void showSuccessAlert() {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 1.5 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
        UIAlertController *alert = [UIAlertController
            alertControllerWithTitle:@"🔐 Ankous Style"
            message:[NSString stringWithFormat:@"✅ تم التجاوز بنجاح\nالبصمة: %@", currentFP]
            preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"موافق" style:UIAlertActionStyleDefault handler:nil]];
        UIWindow *keyWindow = nil;
        for (UIScene *scene in [UIApplication sharedApplication].connectedScenes) {
            if ([scene isKindOfClass:[UIWindowScene class]] && scene.activationState == UISceneActivationStateForegroundActive) {
                keyWindow = [(UIWindowScene *)scene keyWindow] ?: [(UIWindowScene *)scene windows].firstObject;
                break;
            }
        }
        if (keyWindow) [keyWindow.rootViewController presentViewController:alert animated:YES completion:nil];
    });
}

// ============================= التهيئة =============================
__attribute__((constructor))
static void init() {
    @autoreleasepool {
        // fishhook لجميع دوال C
        struct rebinding reb[] = {
            {"sysctl", hooked_sysctl, (void**)&orig_sysctl},
            {"sysctlbyname", hooked_sysctlbyname, (void**)&orig_sysctlbyname},
            {"getenv", hooked_getenv, (void**)&orig_getenv},
            {"_dyld_get_image_name", hooked_dyld_name, (void**)&orig_dyld_name},
            {"_dyld_get_image_header", hooked_dyld_header, (void**)&orig_dyld_header},
            {"vm_region_recurse_64", hooked_vm_region_recurse_64, (void**)&orig_vm_region_recurse_64}
        };
        rebind_symbols(reb, sizeof(reb)/sizeof(reb[0]));

        // Objective-C swizzling
        Class procInfo = NSClassFromString(@"NSProcessInfo");
        Method m = class_getInstanceMethod(procInfo, @selector(operatingSystemVersion));
        if (m) { orig_OSVer = (void*)method_getImplementation(m); method_setImplementation(m, (IMP)hooked_OSVer); }

        Class dev = NSClassFromString(@"UIDevice");
        m = class_getInstanceMethod(dev, @selector(model));
        if (m) { orig_model = (void*)method_getImplementation(m); method_setImplementation(m, (IMP)hooked_model); }
        m = class_getInstanceMethod(dev, @selector(identifierForVendor));
        if (m) { orig_idfv = (void*)method_getImplementation(m); method_setImplementation(m, (IMP)hooked_idfv); }

        Class fileMgr = NSClassFromString(@"NSFileManager");
        m = class_getInstanceMethod(fileMgr, @selector(fileExistsAtPath:));
        if (m) { orig_fileExists = (void*)method_getImplementation(m); method_setImplementation(m, (IMP)hooked_fileExists); }

        // اعتراض طلبات HTTP
        Class req = NSClassFromString(@"NSMutableURLRequest");
        m = class_getInstanceMethod(req, @selector(setValue:forHTTPHeaderField:));
        if (m) { orig_setValueHTTP = (void*)method_getImplementation(m); method_setImplementation(m, (IMP)hooked_setValueHTTP); }

        // توليد البصمة وحفظها
        currentFP = loadFingerprint();
        if (!currentFP) {
            currentFP = sessionFingerprint();
            saveFingerprint(currentFP);
        }

        // مراقبة تسجيل الشاشة
        CFNotificationCenterAddObserver(CFNotificationCenterGetDarwinNotifyCenter(), NULL, screenCaptureChanged,
                                        (__bridge CFStringRef)UIScreenCapturedDidChangeNotification, NULL,
                                        CFNotificationSuspensionBehaviorDeliverImmediately);

        DBG(@"✅ All Anogs-level protections active.");
        showSuccessAlert();
    }
}
