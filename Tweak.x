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

// ============================================================
// أداة مساعدة للطباعة الآمنة
// ============================================================
#define DBG(fmt, ...) NSLog(@"[BYPASS] " fmt, ##__VA_ARGS__)

// ============================================================
// 1. تعطيل sysctl (إخفاء العمليات والـ debugger)
// ============================================================
static int (*orig_sysctl)(int *, u_int, void *, size_t *, void *, size_t);
static int hooked_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    // منع أي طلب لفحص العمليات (KERN_PROC)
    if (namelen >= 2 && name[0] == CTL_KERN && name[1] == KERN_PROC) {
        return -1; // فشل آمن
    }
    return orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen);
}

// ============================================================
// 2. منع ptrace دون استخدام ملف الرأس المفقود
// ============================================================
// تعريف ثابت PT_DENY_ATTACH يدوياً (قيمته 31)
#define PT_DENY_ATTACH 31

// نعرّف دالة ptrace بأنفسنا بنفس signature النظام
static int (*orig_ptrace)(int, pid_t, caddr_t, int);
static int hooked_ptrace(int request, pid_t pid, caddr_t addr, int data) {
    // إذا حاول التطبيق الاتصال بـ PT_DENY_ATTACH نرفضه بصمت
    if (request == PT_DENY_ATTACH) {
        return 0; // نجاح وهمي، لا نسمح بتعطيل التصحيح
    }
    return orig_ptrace(request, pid, addr, data);
}

// ============================================================
// 3. تزوير معلومات النظام (إصدار iOS، الموديل، IDFV، uname)
// ============================================================
static NSOperatingSystemVersion (*orig_OSVersion)(id, SEL);
static NSOperatingSystemVersion hooked_OSVersion(id self, SEL _cmd) {
    return (NSOperatingSystemVersion){17, 4, 1};
}

static NSString* (*orig_model)(UIDevice*, SEL);
static NSString* hooked_model(UIDevice *self, SEL _cmd) {
    return @"iPhone15,3";
}

static NSUUID* (*orig_idfv)(UIDevice*, SEL);
static NSUUID* hooked_idfv(UIDevice *self, SEL _cmd) {
    return [[NSUUID alloc] initWithUUIDString:@"E621E1F8-C36C-495A-93FC-0C247A3E6E5F"];
}

static int (*orig_uname)(struct utsname *);
static int hooked_uname(struct utsname *buf) {
    int ret = orig_uname(buf);
    if (ret == 0 && buf) {
        strlcpy(buf->machine, "iPhone15,3", sizeof(buf->machine));
        strlcpy(buf->nodename, "iPhone", sizeof(buf->nodename));
        strlcpy(buf->release, "22.4.0", sizeof(buf->release));
    }
    return ret;
}

// ============================================================
// 4. إخفاء ملفات الجيلبريك وأدوات التحليل
// ============================================================
static BOOL (*orig_fileExists)(id, SEL, NSString*);
static BOOL hooked_fileExists(id self, SEL _cmd, NSString *path) {
    NSArray *blacklist = @[
        @"frida", @"cycript", @"substrate", @"Cydia", @"Sileo",
        @"Terminal", @"iTerm", @"gdb", @"lldb", @"debugserver",
        @"openssh", @"apt", @"dpkg"
    ];
    for (NSString *word in blacklist) {
        if ([path rangeOfString:word options:NSCaseInsensitiveSearch].location != NSNotFound)
            return NO;
    }
    return orig_fileExists(self, _cmd, path);
}

// ============================================================
// 5. إخفاء مكتبتنا من قائمة dyld
// ============================================================
typedef const struct mach_header* (*dyld_get_image_header_t)(uint32_t);
typedef const char* (*dyld_get_image_name_t)(uint32_t);
static dyld_get_image_header_t orig_get_image_header;
static dyld_get_image_name_t orig_get_image_name;

static const char* hooked_dyld_get_image_name(uint32_t idx) {
    const char *name = orig_get_image_name(idx);
    if (name && strstr(name, "UltimateBypass.dylib")) {
        return "";
    }
    return name;
}

static const struct mach_header* hooked_dyld_get_image_header(uint32_t idx) {
    const char *name = orig_get_image_name(idx);
    if (name && strstr(name, "UltimateBypass.dylib")) {
        return NULL;
    }
    return orig_get_image_header(idx);
}

// ============================================================
// 6. توليد بصمة رقمية متغيرة لكل جلسة (تقنية 726/106)
// ============================================================
static NSString* generateSessionFingerprint() {
    NSString *sessionUUID = [[NSUUID UUID] UUIDString];
    NSTimeInterval ts = [[NSDate date] timeIntervalSince1970];
    NSString *timestamp = [NSString stringWithFormat:@"%.0f", ts * 1000];
    int magic = 106 + arc4random_uniform(1000000);
    NSString *code = [NSString stringWithFormat:@"%d", magic];
    NSString *raw = [NSString stringWithFormat:@"%@|%@|%@|726", sessionUUID, timestamp, code];

    const char *key = [sessionUUID cStringUsingEncoding:NSUTF8StringEncoding];
    const char *data = [raw cStringUsingEncoding:NSUTF8StringEncoding];
    unsigned char hmac[CC_SHA256_DIGEST_LENGTH];
    CCHmac(kCCHmacAlgSHA256, key, strlen(key), data, strlen(data), hmac);
    NSMutableString *fp = [NSMutableString stringWithCapacity:64];
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++)
        [fp appendFormat:@"%02x", hmac[i]];
    return [fp substringToIndex:64];
}

// ============================================================
// 7. اعتراض طلبات الشبكة وحقن البصمة
// ============================================================
static NSString *currentFingerprint = nil;

static void (*orig_setValueForHTTPHeaderField)(id, SEL, NSString*, NSString*);
static void hooked_setValueForHTTPHeaderField(id self, SEL _cmd, NSString *value, NSString *field) {
    if ([field isEqualToString:@"X-Device-Fingerprint"]) {
        value = currentFingerprint;
    }
    orig_setValueForHTTPHeaderField(self, _cmd, value, field);
}

static id (*orig_dataTaskWithRequest)(id, SEL, NSURLRequest*, id);
static id hooked_dataTaskWithRequest(id self, SEL _cmd, NSURLRequest *request, id handler) {
    NSMutableURLRequest *mutableReq = [request mutableCopy];
    if (![mutableReq valueForHTTPHeaderField:@"X-Device-Fingerprint"]) {
        [mutableReq setValue:currentFingerprint forHTTPHeaderField:@"X-Device-Fingerprint"];
    }
    return orig_dataTaskWithRequest(self, _cmd, mutableReq, handler);
}

// ============================================================
// 8. إخفاء متغيرات البيئة المشبوهة (DYLD_INSERT_LIBRARIES)
// ============================================================
static char* (*orig_getenv)(const char *name);
static char* hooked_getenv(const char *name) {
    if (name && (strcmp(name, "DYLD_INSERT_LIBRARIES") == 0 ||
                 strcmp(name, "DYLD_FORCE_FLAT_NAMESPACE") == 0)) {
        return NULL;
    }
    return orig_getenv(name);
}

// ============================================================
// 9. التهيئة النهائية
// ============================================================
__attribute__((constructor))
static void ultimateInit() {
    @autoreleasepool {
        // ---- fishhook ----
        struct rebinding sysctl_rb = {"sysctl", hooked_sysctl, (void**)&orig_sysctl};
        rebind_symbols(&sysctl_rb, 1);

        struct rebinding ptrace_rb = {"ptrace", hooked_ptrace, (void**)&orig_ptrace};
        rebind_symbols(&ptrace_rb, 1);

        struct rebinding uname_rb = {"uname", hooked_uname, (void**)&orig_uname};
        rebind_symbols(&uname_rb, 1);

        struct rebinding getenv_rb = {"getenv", hooked_getenv, (void**)&orig_getenv};
        rebind_symbols(&getenv_rb, 1);

        struct rebinding dyld_rebinds[] = {
            {"_dyld_get_image_name", (void*)hooked_dyld_get_image_name, (void**)&orig_get_image_name},
            {"_dyld_get_image_header", (void*)hooked_dyld_get_image_header, (void**)&orig_get_image_header}
        };
        rebind_symbols(dyld_rebinds, 2);

        // ---- ObjC Swizzling ----
        Class procInfo = NSClassFromString(@"NSProcessInfo");
        Method osVerM = class_getInstanceMethod(procInfo, @selector(operatingSystemVersion));
        if (osVerM) {
            orig_OSVersion = (void*)method_getImplementation(osVerM);
            method_setImplementation(osVerM, (IMP)hooked_OSVersion);
        }

        Class devClass = NSClassFromString(@"UIDevice");
        Method modelM = class_getInstanceMethod(devClass, @selector(model));
        if (modelM) {
            orig_model = (void*)method_getImplementation(modelM);
            method_setImplementation(modelM, (IMP)hooked_model);
        }
        Method idfvM = class_getInstanceMethod(devClass, @selector(identifierForVendor));
        if (idfvM) {
            orig_idfv = (void*)method_getImplementation(idfvM);
            method_setImplementation(idfvM, (IMP)hooked_idfv);
        }

        Class fileMgr = NSClassFromString(@"NSFileManager");
        Method existM = class_getInstanceMethod(fileMgr, @selector(fileExistsAtPath:));
        if (existM) {
            orig_fileExists = (void*)method_getImplementation(existM);
            method_setImplementation(existM, (IMP)hooked_fileExists);
        }

        Class reqClass = NSClassFromString(@"NSMutableURLRequest");
        Method setValM = class_getInstanceMethod(reqClass, @selector(setValue:forHTTPHeaderField:));
        if (setValM) {
            orig_setValueForHTTPHeaderField = (void*)method_getImplementation(setValM);
            method_setImplementation(setValM, (IMP)hooked_setValueForHTTPHeaderField);
        }

        Class sessClass = NSClassFromString(@"NSURLSession");
        Method dataTaskM = class_getInstanceMethod(sessClass, @selector(dataTaskWithRequest:completionHandler:));
        if (dataTaskM) {
            orig_dataTaskWithRequest = (void*)method_getImplementation(dataTaskM);
            method_setImplementation(dataTaskM, (IMP)hooked_dataTaskWithRequest);
        }

        currentFingerprint = generateSessionFingerprint();
        DBG(@"✅ All protections active | Fingerprint: %@", currentFingerprint);
    }
}
