#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <Security/Security.h>
#import <sys/sysctl.h>
#import <dlfcn.h>
#import <objc/runtime.h>
#import <fishhook.h>
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonHMAC.h>
#import <mach-o/dyld.h>
#import <sys/ptrace.h>
#import <unistd.h>

// ============================================================
// 1. تعطيل sysctl (فحص العمليات + الـ debugger)
// ============================================================
static int (*orig_sysctl)(int *, u_int, void *, size_t *, void *, size_t);
static int hooked_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    // منع فحص KERN_PROC
    if (namelen >= 2 && name[0] == CTL_KERN && name[1] == KERN_PROC) {
        return -1;
    }
    // عند طلب معلومات عملية معينة (P_TRACED)
    if (namelen == 4 && name[0] == CTL_KERN && name[1] == KERN_PROC && name[2] == KERN_PROC_PID) {
        if (oldp && oldlenp && *oldlenp >= sizeof(struct kinfo_proc)) {
            struct kinfo_proc *info = (struct kinfo_proc *)oldp;
            info->kp_proc.p_flag &= ~P_TRACED; // إزالة علامة التتبع
        }
        return orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen);
    }
    return orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen);
}

// ============================================================
// 2. منع ptrace (لإعاقة الـ debuggers)
// ============================================================
static int (*orig_ptrace)(int request, pid_t pid, caddr_t addr, int data);
static int hooked_ptrace(int request, pid_t pid, caddr_t addr, int data) {
    if (request == PT_DENY_ATTACH) {
        // نسمح به لمنع اللعبة من استخدامها لمنعنا، لكننا سنمنعها من النجاح
        return 0; // نظهر أننا منعنا التصحيح لكن لا نفعله فعلاً
    }
    if (request == PT_ATTACH || request == PT_ATTACHEXC) {
        return -1; // لا يمكن الارتباط
    }
    return orig_ptrace(request, pid, addr, data);
}

// ============================================================
// 3. تزوير مواصفات النظام
// ============================================================
static NSOperatingSystemVersion (*orig_OSVersion)(id, SEL);
static NSOperatingSystemVersion hooked_OSVersion(id self, SEL _cmd) {
    NSOperatingSystemVersion ver = { .majorVersion = 17, .minorVersion = 5, .patchVersion = 1 };
    return ver;
}

static NSString* (*orig_deviceModel)(UIDevice*, SEL);
static NSString* hooked_deviceModel(UIDevice *self, SEL _cmd) {
    return @"iPhone16,2"; // موديل حديث
}

static NSString* (*orig_systemVersion)(UIDevice*, SEL);
static NSString* hooked_systemVersion(UIDevice *self, SEL _cmd) {
    return @"17.5.1";
}

static NSUUID* (*orig_idfv)(UIDevice*, SEL);
static NSUUID* hooked_idfv(UIDevice *self, SEL _cmd) {
    // قيمة ثابتة غير مرتبطة بالجهاز الحقيقي
    return [[NSUUID alloc] initWithUUIDString:@"F1E2D3C4-B5A6-4978-8901-234567890ABC"];
}

// ============================================================
// 4. إخفاء أي ملفات أدوات (تجاوز فحص الجيلبريك)
// ============================================================
static BOOL (*orig_fileExists)(NSFileManager*, SEL, NSString*);
static BOOL hooked_fileExists(NSFileManager *self, SEL _cmd, NSString *path) {
    NSArray *forbidden = @[
        @"frida", @"cycript", @"substrate", @"Cydia", @"Sileo",
        @"Terminal", @"iTerm", @"gdb", @"lldb", @"debugserver",
        @"apt", @"dpkg", @"bash", @"sh", @"zsh"
    ];
    for (NSString *word in forbidden) {
        if ([path rangeOfString:word options:NSCaseInsensitiveSearch].location != NSNotFound)
            return NO;
    }
    return orig_fileExists(self, _cmd, path);
}

// منع فتح روابط Cydia/Sileo
static id (*orig_openURL)(UIApplication*, SEL, NSURL*);
static id hooked_openURL(UIApplication *self, SEL _cmd, NSURL *url) {
    if ([url.scheme isEqualToString:@"cydia"] || [url.scheme isEqualToString:@"sileo"])
        return nil;
    return orig_openURL(self, _cmd, url);
}

// ============================================================
// 5. إخفاء مكتبتنا من قائمة dyld (منع كشف الحقن)
// ============================================================
static const char* (*orig_dyld_get_image_name)(uint32_t);
static const char* hooked_dyld_get_image_name(uint32_t idx) {
    const char *name = orig_dyld_get_image_name(idx);
    if (name && strstr(name, "PhantomUltimate.dylib"))
        return ""; // إخفاء الاسم
    return name;
}

static const struct mach_header* (*orig_dyld_get_image_header)(uint32_t);
static const struct mach_header* hooked_dyld_get_image_header(uint32_t idx) {
    const char *name = orig_dyld_get_image_name(idx);
    if (name && strstr(name, "PhantomUltimate.dylib"))
        return NULL;
    return orig_dyld_get_image_header(idx);
}

// ============================================================
// 6. توليد بصمة رقمية ديناميكية (تتغير كل مرة يفتح التطبيق)
//    تم دمج الأرقام 726 و 106 لزيادة القوة
// ============================================================
static NSString* generateDynamicFingerprint() {
    // جلسة UUID فريدة
    NSString *sessionUUID = [[NSUUID UUID] UUIDString];
    
    // طابع زمني دقيق (ميلي ثانية)
    NSTimeInterval ts = [[NSDate date] timeIntervalSince1970];
    NSString *timestamp = [NSString stringWithFormat:@"%.0f", ts * 1000];
    
    // رقم سري مضاف (106)
    int random106 = arc4random_uniform(1060000) + 106;
    NSString *secret = [NSString stringWithFormat:@"%d", random106];
    
    // دمج مع الرقم 726
    NSString *raw = [NSString stringWithFormat:@"%@|%@|%@|726", sessionUUID, timestamp, secret];
    
    // مفتاح HMAC من الجلسة
    const char *key = [sessionUUID cStringUsingEncoding:NSUTF8StringEncoding];
    const char *data = [raw cStringUsingEncoding:NSUTF8StringEncoding];
    
    unsigned char hmac[CC_SHA256_DIGEST_LENGTH];
    CCHmac(kCCHmacAlgSHA256, key, strlen(key), data, strlen(data), hmac);
    
    NSMutableString *fingerprint = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH*2];
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++)
        [fingerprint appendFormat:@"%02x", hmac[i]];
    
    return [fingerprint substringToIndex:64];
}

// ============================================================
// 7. اعتراض طلبات الشبكة وحقن البصمة الديناميكية
// ============================================================
static NSString *currentFingerprint = nil;

static void (*orig_setValueForHTTPHeaderField)(NSMutableURLRequest*, SEL, NSString*, NSString*);
static void hooked_setValueForHTTPHeaderField(NSMutableURLRequest *self, SEL _cmd, NSString *value, NSString *field) {
    if ([field isEqualToString:@"X-Device-Fingerprint"]) {
        // نستبدل أي بصمة قديمة بالجديدة
        value = currentFingerprint;
    }
    orig_setValueForHTTPHeaderField(self, _cmd, value, field);
}

static id (*orig_dataTaskWithRequest)(NSURLSession*, SEL, NSURLRequest*, id);
static id hooked_dataTaskWithRequest(NSURLSession *self, SEL _cmd, NSURLRequest *request, id completionHandler) {
    NSMutableURLRequest *mutableRequest = [request mutableCopy];
    if (![mutableRequest valueForHTTPHeaderField:@"X-Device-Fingerprint"]) {
        [mutableRequest setValue:currentFingerprint forHTTPHeaderField:@"X-Device-Fingerprint"];
    }
    return orig_dataTaskWithRequest(self, _cmd, mutableRequest, completionHandler);
}

// ============================================================
// 8. المُهيئ العام – يُنفذ عند تحميل المكتبة في ذاكرة اللعبة
// ============================================================
__attribute__((constructor))
static void ultimateInit() {
    @autoreleasepool {
        // ---- fishhook hooks ----
        struct rebinding binds[] = {
            {"sysctl", hooked_sysctl, (void**)&orig_sysctl},
            {"ptrace", hooked_ptrace, (void**)&orig_ptrace},
            {"_dyld_get_image_name", hooked_dyld_get_image_name, (void**)&orig_dyld_get_image_name},
            {"_dyld_get_image_header", hooked_dyld_get_image_header, (void**)&orig_dyld_get_image_header}
        };
        rebind_symbols(binds, sizeof(binds)/sizeof(struct rebinding));
        
        // ---- Objective‑C swizzling ----
        // NSProcessInfo
        Class procInfo = NSClassFromString(@"NSProcessInfo");
        Method osVerMeth = class_getInstanceMethod(procInfo, @selector(operatingSystemVersion));
        if (osVerMeth) {
            orig_OSVersion = (void*)method_getImplementation(osVerMeth);
            method_setImplementation(osVerMeth, (IMP)hooked_OSVersion);
        }
        
        // UIDevice
        Class dev = NSClassFromString(@"UIDevice");
        Method modelMeth = class_getInstanceMethod(dev, @selector(model));
        if (modelMeth) {
            orig_deviceModel = (void*)method_getImplementation(modelMeth);
            method_setImplementation(modelMeth, (IMP)hooked_deviceModel);
        }
        Method sysVerMeth = class_getInstanceMethod(dev, @selector(systemVersion));
        if (sysVerMeth) {
            orig_systemVersion = (void*)method_getImplementation(sysVerMeth);
            method_setImplementation(sysVerMeth, (IMP)hooked_systemVersion);
        }
        Method idfvMeth = class_getInstanceMethod(dev, @selector(identifierForVendor));
        if (idfvMeth) {
            orig_idfv = (void*)method_getImplementation(idfvMeth);
            method_setImplementation(idfvMeth, (IMP)hooked_idfv);
        }
        
        // NSFileManager
        Class fileMgr = NSClassFromString(@"NSFileManager");
        Method fileExistsMeth = class_getInstanceMethod(fileMgr, @selector(fileExistsAtPath:));
        if (fileExistsMeth) {
            orig_fileExists = (void*)method_getImplementation(fileExistsMeth);
            method_setImplementation(fileExistsMeth, (IMP)hooked_fileExists);
        }
        
        // UIApplication (openURL)
        Class app = NSClassFromString(@"UIApplication");
        Method openURLMeth = class_getInstanceMethod(app, @selector(openURL:));
        if (openURLMeth) {
            orig_openURL = (void*)method_getImplementation(openURLMeth);
            method_setImplementation(openURLMeth, (IMP)hooked_openURL);
        }
        
        // شبكة
        Class req = NSClassFromString(@"NSMutableURLRequest");
        Method setHeaderMeth = class_getInstanceMethod(req, @selector(setValue:forHTTPHeaderField:));
        if (setHeaderMeth) {
            orig_setValueForHTTPHeaderField = (void*)method_getImplementation(setHeaderMeth);
            method_setImplementation(setHeaderMeth, (IMP)hooked_setValueForHTTPHeaderField);
        }
        
        Class session = NSClassFromString(@"NSURLSession");
        Method dataTaskMeth = class_getInstanceMethod(session, @selector(dataTaskWithRequest:completionHandler:));
        if (dataTaskMeth) {
            orig_dataTaskWithRequest = (void*)method_getImplementation(dataTaskMeth);
            method_setImplementation(dataTaskMeth, (IMP)hooked_dataTaskWithRequest);
        }
        
        // توليد البصمة الديناميكية للجلسة الحالية
        currentFingerprint = generateDynamicFingerprint();
        NSLog(@"🔐 PHANTOM ULTIMATE ACTIVE – FINGERPRINT: %@", currentFingerprint);
    }
}