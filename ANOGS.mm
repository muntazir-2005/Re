#import <stdio.h>
#import <string.h>
#import <unistd.h>
#import <stdlib.h>
#import <sys/stat.h>
#import <sys/sysctl.h>
#import <sys/utsname.h>
#import <dlfcn.h>
#import <mach/mach.h>
#import <mach-o/dyld.h>
#import <TargetConditionals.h>
#import <sys/param.h>
#import <sys/mount.h>
#import <CommonCrypto/CommonCryptor.h>
#import <Security/Security.h>
#import <Security/SecKey.h>
#import <time.h>
#import <dispatch/dispatch.h>
#import <sys/syscall.h>
#import <pthread.h>

#if TARGET_OS_IPHONE
#import <objc/runtime.h>
#import <objc/message.h>
#import <LocalAuthentication/LocalAuthentication.h>
#import <UIKit/UIKit.h>
#endif

#include "fishhook.h"

// تعريف هيكل dummy لـ AES_KEY لأن OpenSSL غير موجود في iOS SDK
typedef struct { int dummy; } AES_KEY;

// ptrace
#define PT_DENY_ATTACH 31
typedef int (*ptrace_ptr_t)(int, pid_t, caddr_t, int);
static ptrace_ptr_t real_ptrace = NULL;
static void load_real_ptrace(void) {
    if (!real_ptrace) real_ptrace = (ptrace_ptr_t)dlsym(RTLD_DEFAULT, "ptrace");
}
static int my_ptrace(int request, pid_t pid, caddr_t addr, int data) {
    if (request == PT_DENY_ATTACH) return 0;
    load_real_ptrace();
    return real_ptrace ? real_ptrace(request, pid, addr, data) : 0;
}

// ========== Original function pointers ==========
static int (*orig_sysctl)(int*, u_int, void*, size_t*, void*, size_t);
static int (*orig_sysctlbyname)(const char*, void*, size_t*, void*, size_t);
static void* (*orig_dlopen)(const char*, int);
static void* (*orig_dlsym)(void*, const char*);
static int (*orig_task_for_pid)(mach_port_t, int, mach_port_t*);
static int (*orig_vm_read_overwrite)(vm_map_t, vm_address_t, vm_size_t, vm_address_t, vm_size_t*);
static int (*orig_vm_write)(vm_map_t, vm_address_t, vm_offset_t, mach_msg_type_number_t);
static int (*orig_vm_protect)(vm_map_t, vm_address_t, vm_size_t, boolean_t, vm_prot_t);
static int (*orig_mach_vm_protect)(vm_map_t, mach_vm_address_t, mach_vm_size_t, boolean_t, vm_prot_t);
static OSStatus (*orig_SecItemCopyMatching)(CFDictionaryRef, CFTypeRef*);
static OSStatus (*orig_SecItemAdd)(CFDictionaryRef, CFTypeRef*);
static OSStatus (*orig_SecItemUpdate)(CFDictionaryRef, CFDictionaryRef);
static OSStatus (*orig_SecItemDelete)(CFDictionaryRef);
static SecKeyRef (*orig_SecKeyCreateRandomKey)(CFDictionaryRef, CFErrorRef*);
static SecKeyRef (*orig_SecKeyCopyPublicKey)(SecKeyRef);
static CFDataRef (*orig_SecKeyCreateSignature)(SecKeyRef, SecKeyAlgorithm, CFDataRef, CFErrorRef*);
static Boolean (*orig_SecKeyVerifySignature)(SecKeyRef, SecKeyAlgorithm, CFDataRef, CFDataRef, CFErrorRef*);
static CCCryptorStatus (*orig_CCCrypt)(CCOperation, CCAlgorithm, CCOptions, const void*, size_t, const void*, const void*, size_t, void*, size_t, size_t*);

// الدوال الجديدة المطلوبة
static int (*orig_task_info)(task_name_t, task_flavor_t, task_info_t, mach_msg_type_number_t*);
static int (*orig_task_get_special_port)(task_t, int, mach_port_t*);
static int (*orig_stat)(const char*, struct stat*);
static int (*orig_lstat)(const char*, struct stat*);
static int (*orig_statfs)(const char*, struct statfs*);
static FILE* (*orig_fopen)(const char*, const char*);
static int (*orig_access)(const char*, int);
static int (*orig_proc_regionfilename)(int, uint64_t, char*, uint32_t);
static kern_return_t (*orig_mach_vm_region_recurse)(vm_map_t, mach_vm_address_t*, mach_vm_size_t*, uint32_t*, natural_t*);
static int (*orig_dladdr)(const void*, Dl_info*);
static int (*orig_getmntinfo)(struct statfs**, int);
static int (*orig_csops)(pid_t, unsigned int, void*, size_t);
static int (*orig_pthread_create)(pthread_t*, const pthread_attr_t*, void*(*)(void*), void*);
static int (*orig_pthread_attr_init)(pthread_attr_t*);
static int (*orig_pthread_attr_setdetachstate)(pthread_attr_t*, int);
static int (*orig_pthread_attr_setstacksize)(pthread_attr_t*, size_t);
static int (*orig_pthread_attr_destroy)(pthread_attr_t*);
static void (*orig_AES_encrypt)(const unsigned char*, unsigned char*, const AES_KEY*);
static void (*orig_aes_cbc_encrypt)(const unsigned char*, unsigned char*, size_t, const AES_KEY*, unsigned char*, const int);
static void (*orig_rijndael)(void*, void*, const void*);

// ========== Replacement functions ==========
static int my_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    int ret = orig_sysctl ? orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen) : 0;
    if (ret == 0 && oldp && namelen == 4 && name[0] == CTL_KERN && name[1] == KERN_PROC && name[2] == KERN_PROC_PID) {
        struct kinfo_proc *kp = (struct kinfo_proc *)oldp;
        kp->kp_proc.p_flag &= ~P_TRACED;
    }
    return ret;
}
static int my_sysctlbyname(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    if (oldp && oldlenp && (strstr(name, "debug") || strstr(name, "kern.proc"))) {
        memset(oldp, 0, *oldlenp);
        return 0;
    }
    return orig_sysctlbyname ? orig_sysctlbyname(name, oldp, oldlenp, newp, newlen) : 0;
}
static void* my_dlopen(const char *path, int mode) {
    return orig_dlopen ? orig_dlopen(path, mode) : NULL;
}
static void* my_dlsym(void *handle, const char *symbol) {
    if (symbol && (strstr(symbol, "ptrace") || strstr(symbol, "sysctl") || strstr(symbol, "task_for_pid") || strstr(symbol, "vm_read")))
        return NULL;
    return orig_dlsym ? orig_dlsym(handle, symbol) : NULL;
}
static int my_task_for_pid(mach_port_t tport, int pid, mach_port_t *tn) { return KERN_FAILURE; }
static int my_vm_read_overwrite(vm_map_t task, vm_address_t addr, vm_size_t size, vm_address_t data, vm_size_t *out) { return KERN_FAILURE; }
static int my_vm_write(vm_map_t task, vm_address_t addr, vm_offset_t data, mach_msg_type_number_t cnt) { return KERN_FAILURE; }
static int my_vm_protect(vm_map_t task, vm_address_t addr, vm_size_t size, boolean_t max, vm_prot_t prot) { return KERN_SUCCESS; }
static int my_mach_vm_protect(vm_map_t task, mach_vm_address_t addr, mach_vm_size_t size, boolean_t max, vm_prot_t prot) { return KERN_SUCCESS; }
static OSStatus my_SecItemCopyMatching(CFDictionaryRef q, CFTypeRef *r) { return errSecItemNotFound; }
static OSStatus my_SecItemAdd(CFDictionaryRef a, CFTypeRef *r) { return errSecDuplicateItem; }
static OSStatus my_SecItemUpdate(CFDictionaryRef q, CFDictionaryRef a) { return errSecItemNotFound; }
static OSStatus my_SecItemDelete(CFDictionaryRef q) { return errSecSuccess; }
static SecKeyRef my_SecKeyCreateRandomKey(CFDictionaryRef p, CFErrorRef *e) { return NULL; }
static SecKeyRef my_SecKeyCopyPublicKey(SecKeyRef k) { return NULL; }
static CFDataRef my_SecKeyCreateSignature(SecKeyRef k, SecKeyAlgorithm a, CFDataRef d, CFErrorRef *e) { return CFDataCreate(NULL, (const UInt8*)"fake", 4); }
static Boolean my_SecKeyVerifySignature(SecKeyRef k, SecKeyAlgorithm a, CFDataRef d, CFDataRef s, CFErrorRef *e) { return true; }
static CCCryptorStatus my_CCCrypt(CCOperation op, CCAlgorithm alg, CCOptions opt, const void *key, size_t kLen, const void *iv, const void *in, size_t inLen, void *out, size_t outAvail, size_t *outMoved) {
    if (!out || !outMoved) return kCCParamError;
    size_t bytes = (inLen < outAvail) ? inLen : outAvail;
    memcpy(out, in, bytes);
    *outMoved = bytes;
    return (bytes == inLen) ? kCCSuccess : kCCBufferTooSmall;
}

// هوكات الدوال الجديدة
static int my_task_info(task_name_t task, task_flavor_t flavor, task_info_t info, mach_msg_type_number_t *count) { return KERN_FAILURE; }
static int my_task_get_special_port(task_t task, int which, mach_port_t *port) { return KERN_FAILURE; }
static int my_stat(const char *path, struct stat *buf) { return -1; }
static int my_lstat(const char *path, struct stat *buf) { return -1; }
static int my_statfs(const char *path, struct statfs *buf) { return -1; }
static FILE* my_fopen(const char *path, const char *mode) { return NULL; }
static int my_access(const char *path, int mode) { return -1; }
static int my_proc_regionfilename(int pid, uint64_t addr, char *buf, uint32_t len) { return 0; }
static kern_return_t my_mach_vm_region_recurse(vm_map_t map, mach_vm_address_t *addr, mach_vm_size_t *size, uint32_t *depth, natural_t *info) { return KERN_FAILURE; }
static int my_dladdr(const void *addr, Dl_info *info) { return 0; }
static int my_getmntinfo(struct statfs **mntbufp, int flags) { return 0; }
static int my_csops(pid_t pid, unsigned int ops, void *data, size_t len) { return 0; }
static int my_pthread_create(pthread_t *thread, const pthread_attr_t *attr, void*(*start)(void*), void *arg) { return -1; } // منع إنشاء خيوط جديدة
static int my_pthread_attr_init(pthread_attr_t *attr) { return orig_pthread_attr_init ? orig_pthread_attr_init(attr) : -1; }
static int my_pthread_attr_setdetachstate(pthread_attr_t *attr, int state) { return orig_pthread_attr_setdetachstate ? orig_pthread_attr_setdetachstate(attr, state) : -1; }
static int my_pthread_attr_setstacksize(pthread_attr_t *attr, size_t size) { return orig_pthread_attr_setstacksize ? orig_pthread_attr_setstacksize(attr, size) : -1; }
static int my_pthread_attr_destroy(pthread_attr_t *attr) { return orig_pthread_attr_destroy ? orig_pthread_attr_destroy(attr) : -1; }
static void my_AES_encrypt(const unsigned char *in, unsigned char *out, const AES_KEY *key) { if (out) memset(out, 0, 16); }
static void my_aes_cbc_encrypt(const unsigned char *in, unsigned char *out, size_t len, const AES_KEY *key, unsigned char *ivec, const int enc) { if (out) memset(out, 0, len); }
static void my_rijndael(void *in, void *out, const void *key) { if (out) memset(out, 0, 16); }

// ========== Objective-C swizzling ==========
static IMP orig_UIDevice_identifierForVendor;
static id my_UIDevice_identifierForVendor(id self, SEL _cmd) {
    return [[NSUUID alloc] initWithUUIDString:@"00000000-0000-0000-0000-000000000000"];
}
static void my_LAContext_evaluatePolicy(id self, SEL _cmd, LAPolicy policy, NSString *reason, void(^reply)(BOOL, NSError*)) {
    if (reply) reply(YES, nil);
}
static BOOL my_LAContext_canEvaluatePolicy(id self, SEL _cmd, LAPolicy policy, NSError **error) { return YES; }
void swizzle_objc_methods() {
    Class deviceCls = objc_getClass("UIDevice");
    if (deviceCls) {
        SEL sel = @selector(identifierForVendor);
        Method m = class_getInstanceMethod(deviceCls, sel);
        if (m) method_setImplementation(m, (IMP)my_UIDevice_identifierForVendor);
    }
    Class laContextCls = objc_getClass("LAContext");
    if (laContextCls) {
        SEL sel1 = @selector(evaluatePolicy:localizedReason:reply:);
        Method m1 = class_getInstanceMethod(laContextCls, sel1);
        if (m1) method_setImplementation(m1, (IMP)my_LAContext_evaluatePolicy);
        SEL sel2 = @selector(canEvaluatePolicy:error:);
        Method m2 = class_getInstanceMethod(laContextCls, sel2);
        if (m2) method_setImplementation(m2, (IMP)my_LAContext_canEvaluatePolicy);
    }
}

// ========== إظهار شعار الحماية فوراً ==========
void show_protection_logo() {
    NSLog(@"⚠️ تم تشغيل الحماية - Protection Active ⚠️");
#if TARGET_OS_IPHONE
    dispatch_async(dispatch_get_main_queue(), ^{
        UIWindow *keyWindow = [UIApplication sharedApplication].keyWindow;
        if (keyWindow) {
            UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"الحماية"
                                                                           message:@"تم تشغيل الحماية بنجاح"
                                                                    preferredStyle:UIAlertControllerStyleAlert];
            [keyWindow.rootViewController presentViewController:alert animated:YES completion:nil];
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
                [alert dismissViewControllerAnimated:YES completion:nil];
            });
        }
    });
#endif
}

// ========== ربط الدوال باستخدام fishhook ==========
void fishhook_bindings() {
    struct rebinding bindings[] = {
        {"sysctl", (void*)my_sysctl, (void**)&orig_sysctl},
        {"sysctlbyname", (void*)my_sysctlbyname, (void**)&orig_sysctlbyname},
        {"dlopen", (void*)my_dlopen, (void**)&orig_dlopen},
        {"dlsym", (void*)my_dlsym, (void**)&orig_dlsym},
        {"task_for_pid", (void*)my_task_for_pid, (void**)&orig_task_for_pid},
        {"vm_read_overwrite", (void*)my_vm_read_overwrite, (void**)&orig_vm_read_overwrite},
        {"vm_write", (void*)my_vm_write, (void**)&orig_vm_write},
        {"vm_protect", (void*)my_vm_protect, (void**)&orig_vm_protect},
        {"mach_vm_protect", (void*)my_mach_vm_protect, (void**)&orig_mach_vm_protect},
        {"SecItemCopyMatching", (void*)my_SecItemCopyMatching, (void**)&orig_SecItemCopyMatching},
        {"SecItemAdd", (void*)my_SecItemAdd, (void**)&orig_SecItemAdd},
        {"SecItemUpdate", (void*)my_SecItemUpdate, (void**)&orig_SecItemUpdate},
        {"SecItemDelete", (void*)my_SecItemDelete, (void**)&orig_SecItemDelete},
        {"SecKeyCreateRandomKey", (void*)my_SecKeyCreateRandomKey, (void**)&orig_SecKeyCreateRandomKey},
        {"SecKeyCopyPublicKey", (void*)my_SecKeyCopyPublicKey, (void**)&orig_SecKeyCopyPublicKey},
        {"SecKeyCreateSignature", (void*)my_SecKeyCreateSignature, (void**)&orig_SecKeyCreateSignature},
        {"SecKeyVerifySignature", (void*)my_SecKeyVerifySignature, (void**)&orig_SecKeyVerifySignature},
        {"CCCrypt", (void*)my_CCCrypt, (void**)&orig_CCCrypt},
        {"task_info", (void*)my_task_info, (void**)&orig_task_info},
        {"task_get_special_port", (void*)my_task_get_special_port, (void**)&orig_task_get_special_port},
        {"stat", (void*)my_stat, (void**)&orig_stat},
        {"lstat", (void*)my_lstat, (void**)&orig_lstat},
        {"statfs", (void*)my_statfs, (void**)&orig_statfs},
        {"fopen", (void*)my_fopen, (void**)&orig_fopen},
        {"access", (void*)my_access, (void**)&orig_access},
        {"proc_regionfilename", (void*)my_proc_regionfilename, (void**)&orig_proc_regionfilename},
        {"mach_vm_region_recurse", (void*)my_mach_vm_region_recurse, (void**)&orig_mach_vm_region_recurse},
        {"dladdr", (void*)my_dladdr, (void**)&orig_dladdr},
        {"getmntinfo", (void*)my_getmntinfo, (void**)&orig_getmntinfo},
        {"csops", (void*)my_csops, (void**)&orig_csops},
        {"pthread_create", (void*)my_pthread_create, (void**)&orig_pthread_create},
        {"pthread_attr_init", (void*)my_pthread_attr_init, (void**)&orig_pthread_attr_init},
        {"pthread_attr_setdetachstate", (void*)my_pthread_attr_setdetachstate, (void**)&orig_pthread_attr_setdetachstate},
        {"pthread_attr_setstacksize", (void*)my_pthread_attr_setstacksize, (void**)&orig_pthread_attr_setstacksize},
        {"pthread_attr_destroy", (void*)my_pthread_attr_destroy, (void**)&orig_pthread_attr_destroy},
        {"AES_encrypt", (void*)my_AES_encrypt, (void**)&orig_AES_encrypt},
        {"aes_cbc_encrypt", (void*)my_aes_cbc_encrypt, (void**)&orig_aes_cbc_encrypt},
        {"rijndael", (void*)my_rijndael, (void**)&orig_rijndael}
    };
    rebind_symbols(bindings, sizeof(bindings)/sizeof(bindings[0]));
}

// ========== Constructor: تفعيل فوري ==========
__attribute__((constructor))
void init_hook() {
    show_protection_logo();        // شعار فوري
    fishhook_bindings();           // ربط جميع الدوال
    swizzle_objc_methods();        // تبديل دوال Objective-C
}
