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
#import <Foundation/Foundation.h>

#if TARGET_OS_IPHONE
#import <objc/runtime.h>
#import <objc/message.h>
#import <LocalAuthentication/LocalAuthentication.h>
#import <UIKit/UIKit.h>
#endif

#include "fishhook.h"

// ptrace – dynamic lookup
#define PT_DENY_ATTACH 31
typedef int (*ptrace_ptr_t)(int, pid_t, caddr_t, int);
static ptrace_ptr_t real_ptrace = NULL;
static void load_real_ptrace(void) {
    if (!real_ptrace) {
        real_ptrace = (ptrace_ptr_t)dlsym(RTLD_DEFAULT, "ptrace");
    }
}

// Original function pointers
static int (*orig_sysctl)(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen);
static int (*orig_sysctlbyname)(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen);
static void* (*orig_dlopen)(const char *path, int mode);
static void* (*orig_dlsym)(void *handle, const char *symbol);
static int (*orig_task_for_pid)(mach_port_t target_tport, int pid, mach_port_t *tn);
static int (*orig_vm_read_overwrite)(vm_map_t target_task, vm_address_t address, vm_size_t size, vm_address_t data, vm_size_t *outsize);
static int (*orig_vm_write)(vm_map_t target_task, vm_address_t address, vm_offset_t data, mach_msg_type_number_t dataCnt);
static int (*orig_vm_protect)(vm_map_t target_task, vm_address_t address, vm_size_t size, boolean_t set_max, vm_prot_t new_protection);
static int (*orig_mach_vm_protect)(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, boolean_t set_max, vm_prot_t new_protection);
static const char* (*orig_dyld_get_image_name)(uint32_t image_index);

// Keychain
static OSStatus (*orig_SecItemCopyMatching)(CFDictionaryRef query, CFTypeRef *result);
static OSStatus (*orig_SecItemAdd)(CFDictionaryRef attributes, CFTypeRef *result);
static OSStatus (*orig_SecItemUpdate)(CFDictionaryRef query, CFDictionaryRef attributesToUpdate);
static OSStatus (*orig_SecItemDelete)(CFDictionaryRef query);

// SecKey
static SecKeyRef (*orig_SecKeyCreateRandomKey)(CFDictionaryRef parameters, CFErrorRef *error);
static SecKeyRef (*orig_SecKeyCopyPublicKey)(SecKeyRef key);
static CFDataRef (*orig_SecKeyCreateSignature)(SecKeyRef key, SecKeyAlgorithm algorithm, CFDataRef dataToSign, CFErrorRef *error);
static Boolean (*orig_SecKeyVerifySignature)(SecKeyRef key, SecKeyAlgorithm algorithm, CFDataRef dataToSign, CFDataRef signature, CFErrorRef *error);

// CommonCrypto
static CCCryptorStatus (*orig_CCCrypt)(CCOperation op, CCAlgorithm alg, CCOptions options, const void *key, size_t keyLength, const void *iv, const void *dataIn, size_t dataInLength, void *dataOut, size_t dataOutAvailable, size_t *dataOutMoved);

// OpenSSL (minimal)
static int (*orig_RSA_verify)(int type, const unsigned char *m, unsigned int m_len, const unsigned char *sig, unsigned int sig_len, RSA *rsa);
static int (*orig_RSA_sign)(int type, const unsigned char *m, unsigned int m_len, unsigned char *sig, unsigned int *sig_len, RSA *rsa);
static int (*orig_EVP_PKEY_verify)(EVP_PKEY_CTX *ctx, const unsigned char *sig, size_t sig_len, const unsigned char *tbs, size_t tbs_len);
static int (*orig_X509_verify_cert)(X509_STORE_CTX *ctx);
static int (*orig_X509_check_private_key)(X509 *x509, EVP_PKEY *pkey);
static EVP_PKEY* (*orig_PEM_read_bio_PrivateKey)(BIO *bp, EVP_PKEY **x, pem_password_cb *cb, void *u);
static int (*orig_SSL_CTX_use_PrivateKey_file)(SSL_CTX *ctx, const char *file, int type);
static int (*orig_SSL_CTX_check_private_key)(SSL_CTX *ctx);
static int (*orig_SSL_CTX_load_verify_locations)(SSL_CTX *ctx, const char *CAfile, const char *CApath);

// Replacement functions – anti-debug
static int my_ptrace(int request, pid_t pid, caddr_t addr, int data) {
    if (request == PT_DENY_ATTACH) return 0;
    load_real_ptrace();
    return real_ptrace ? real_ptrace(request, pid, addr, data) : 0;
}

static int my_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    int ret = orig_sysctl ? orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen) : 0;
    if (ret == 0 && oldp && namelen == 4 && name[0] == CTL_KERN && name[1] == KERN_PROC && name[2] == KERN_PROC_PID) {
        struct kinfo_proc *kp = (struct kinfo_proc *)oldp;
        kp->kp_proc.p_flag &= ~P_TRACED; // remove traced flag
    }
    return ret;
}

static int my_sysctlbyname(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    if (oldp && oldlenp) {
        if (strstr(name, "debug") || strstr(name, "kern.proc") || strstr(name, "sysctl.proc")) {
            memset(oldp, 0, *oldlenp);
            return 0;
        }
    }
    return orig_sysctlbyname ? orig_sysctlbyname(name, oldp, oldlenp, newp, newlen) : 0;
}

static void* my_dlopen(const char *path, int mode) {
    // Block loading of known injection libraries
    if (path) {
        const char *blocklist[] = {"frida", "substrate", "CydiaSubstrate", "hook", "cycript", "Liberty", "Shadow"};
        for (int i = 0; i < sizeof(blocklist)/sizeof(blocklist[0]); i++) {
            if (strstr(path, blocklist[i])) {
                return NULL;
            }
        }
    }
    return orig_dlopen ? orig_dlopen(path, mode) : NULL;
}

static void* my_dlsym(void *handle, const char *symbol) {
    // Hide sensitive symbols
    if (symbol) {
        const char *hidden[] = {"ptrace", "sysctl", "task_for_pid", "vm_read", "jb", "jailbreak", "cydia"};
        for (int i = 0; i < sizeof(hidden)/sizeof(hidden[0]); i++) {
            if (strstr(symbol, hidden[i])) {
                return NULL;
            }
        }
    }
    return orig_dlsym ? orig_dlsym(handle, symbol) : NULL;
}

static int my_task_for_pid(mach_port_t target_tport, int pid, mach_port_t *tn) { return KERN_FAILURE; }
static int my_vm_read_overwrite(vm_map_t target_task, vm_address_t address, vm_size_t size, vm_address_t data, vm_size_t *outsize) { return KERN_FAILURE; }
static int my_vm_write(vm_map_t target_task, vm_address_t address, vm_offset_t data, mach_msg_type_number_t dataCnt) { return KERN_FAILURE; }
static int my_vm_protect(vm_map_t target_task, vm_address_t address, vm_size_t size, boolean_t set_max, vm_prot_t new_protection) {
    return orig_vm_protect ? orig_vm_protect(target_task, address, size, set_max, new_protection) : KERN_SUCCESS;
}
static int my_mach_vm_protect(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, boolean_t set_max, vm_prot_t new_protection) {
    return orig_mach_vm_protect ? orig_mach_vm_protect(target_task, address, size, set_max, new_protection) : KERN_SUCCESS;
}

// Hide loaded image names that contain injection keywords
static const char* my_dyld_get_image_name(uint32_t image_index) {
    const char *original = orig_dyld_get_image_name ? orig_dyld_get_image_name(image_index) : NULL;
    if (original) {
        const char *bad[] = {"substrate", "frida", "cycript", "dylib", "hook", "inject"};
        for (int i = 0; i < sizeof(bad)/sizeof(bad[0]); i++) {
            if (strstr(original, bad[i])) {
                return "";
            }
        }
    }
    return original ? original : "";
}

// Keychain – deny access
static OSStatus my_SecItemCopyMatching(CFDictionaryRef query, CFTypeRef *result) { return errSecItemNotFound; }
static OSStatus my_SecItemAdd(CFDictionaryRef attributes, CFTypeRef *result) { return errSecDuplicateItem; }
static OSStatus my_SecItemUpdate(CFDictionaryRef query, CFDictionaryRef attributesToUpdate) { return errSecItemNotFound; }
static OSStatus my_SecItemDelete(CFDictionaryRef query) { return errSecSuccess; }

// SecKey – fake operations
static SecKeyRef my_SecKeyCreateRandomKey(CFDictionaryRef parameters, CFErrorRef *error) { return NULL; }
static SecKeyRef my_SecKeyCopyPublicKey(SecKeyRef key) { return NULL; }
static CFDataRef my_SecKeyCreateSignature(SecKeyRef key, SecKeyAlgorithm algorithm, CFDataRef dataToSign, CFErrorRef *error) {
    return CFDataCreate(NULL, (const UInt8*)"fake_signature", 14);
}
static Boolean my_SecKeyVerifySignature(SecKeyRef key, SecKeyAlgorithm algorithm, CFDataRef dataToSign, CFDataRef signature, CFErrorRef *error) { return true; }

// CommonCrypto – transparent passthrough
static CCCryptorStatus my_CCCrypt(CCOperation op, CCAlgorithm alg, CCOptions options,
                                  const void *key, size_t keyLength, const void *iv,
                                  const void *dataIn, size_t dataInLength,
                                  void *dataOut, size_t dataOutAvailable,
                                  size_t *dataOutMoved) {
    if (!dataOut || !dataOutMoved) return kCCParamError;
    size_t bytes = (dataInLength < dataOutAvailable) ? dataInLength : dataOutAvailable;
    memcpy(dataOut, dataIn, bytes);
    *dataOutMoved = bytes;
    return (bytes == dataInLength) ? kCCSuccess : kCCBufferTooSmall;
}

// OpenSSL – always succeed
static int my_RSA_verify(int type, const unsigned char *m, unsigned int m_len, const unsigned char *sig, unsigned int sig_len, RSA *rsa) { return 1; }
static int my_RSA_sign(int type, const unsigned char *m, unsigned int m_len, unsigned char *sig, unsigned int *sig_len, RSA *rsa) {
    if (sig_len) *sig_len = 0; return 0;
}
static int my_EVP_PKEY_verify(EVP_PKEY_CTX *ctx, const unsigned char *sig, size_t sig_len, const unsigned char *tbs, size_t tbs_len) { return 1; }
static int my_X509_verify_cert(X509_STORE_CTX *ctx) { return 1; }
static int my_X509_check_private_key(X509 *x509, EVP_PKEY *pkey) { return 1; }
static EVP_PKEY* my_PEM_read_bio_PrivateKey(BIO *bp, EVP_PKEY **x, pem_password_cb *cb, void *u) { return NULL; }
static int my_SSL_CTX_use_PrivateKey_file(SSL_CTX *ctx, const char *file, int type) { return 1; }
static int my_SSL_CTX_check_private_key(SSL_CTX *ctx) { return 1; }
static int my_SSL_CTX_load_verify_locations(SSL_CTX *ctx, const char *CAfile, const char *CApath) { return 1; }

// ============================================================================
// Hook NSFileManager to hide jailbreak/tweak paths
// ============================================================================
static BOOL (*orig_fileExistsAtPath)(id self, SEL cmd, NSString *path);
static BOOL my_fileExistsAtPath(id self, SEL cmd, NSString *path) {
    if (!path) return NO;
    const char *cPath = [path UTF8String];
    const char *suspiciousPaths[] = {
        "/Applications/Cydia.app", "/Library/MobileSubstrate", "/usr/sbin/sshd",
        "/etc/apt", "/private/var/lib/apt", "/var/checkra1n.dmg", "/.bootstrapped",
        "/usr/libexec/cydia", "/usr/sbin/frida-server", "/Developer/usr/bin/debugserver"
    };
    for (int i = 0; i < sizeof(suspiciousPaths)/sizeof(suspiciousPaths[0]); i++) {
        if (strcmp(cPath, suspiciousPaths[i]) == 0) return NO;
    }
    return orig_fileExistsAtPath(self, cmd, path);
}

static NSArray* (*orig_contentsOfDirectoryAtPathError)(id self, SEL cmd, NSString *path, NSError **error);
static NSArray* my_contentsOfDirectoryAtPathError(id self, SEL cmd, NSString *path, NSError **error) {
    NSArray *original = orig_contentsOfDirectoryAtPathError(self, cmd, path, error);
    if (!original) return original;
    // Filter out entries related to tweaks
    NSMutableArray *filtered = [NSMutableArray array];
    for (NSString *item in original) {
        if ([item containsString:@"Cydia"] || [item containsString:@"Substrate"] ||
            [item containsString:@"frida"] || [item containsString:@"cycript"]) {
            continue;
        }
        [filtered addObject:item];
    }
    return filtered;
}

// ============================================================================
// Objective-C swizzling (UI, LAContext)
// ============================================================================
static IMP orig_UIDevice_identifierForVendor;
static id my_UIDevice_identifierForVendor(id self, SEL _cmd) {
    return [[NSUUID alloc] initWithUUIDString:@"00000000-0000-0000-0000-000000000000"];
}

static void my_LAContext_evaluatePolicy(id self, SEL _cmd, LAPolicy policy,
                                        NSString *localizedReason,
                                        void(^reply)(BOOL success, NSError *error)) {
    if (reply) reply(YES, nil);
}

static BOOL my_LAContext_canEvaluatePolicy(id self, SEL _cmd, LAPolicy policy, NSError **error) {
    return YES;
}

void swizzle_objc_methods() {
    // UIDevice
    Class deviceCls = objc_getClass("UIDevice");
    if (deviceCls) {
        SEL sel = @selector(identifierForVendor);
        Method m = class_getInstanceMethod(deviceCls, sel);
        if (m) {
            orig_UIDevice_identifierForVendor = method_getImplementation(m);
            method_setImplementation(m, (IMP)my_UIDevice_identifierForVendor);
        }
    }
    // LAContext
    Class laContextCls = objc_getClass("LAContext");
    if (laContextCls) {
        SEL sel1 = @selector(evaluatePolicy:localizedReason:reply:);
        Method m1 = class_getInstanceMethod(laContextCls, sel1);
        if (m1) method_setImplementation(m1, (IMP)my_LAContext_evaluatePolicy);
        
        SEL sel2 = @selector(canEvaluatePolicy:error:);
        Method m2 = class_getInstanceMethod(laContextCls, sel2);
        if (m2) method_setImplementation(m2, (IMP)my_LAContext_canEvaluatePolicy);
    }
    
    // NSFileManager
    Class fmClass = objc_getClass("NSFileManager");
    if (fmClass) {
        SEL existsSel = @selector(fileExistsAtPath:);
        Method existsMethod = class_getInstanceMethod(fmClass, existsSel);
        if (existsMethod) {
            orig_fileExistsAtPath = (BOOL(*)(id,SEL,NSString*))method_getImplementation(existsMethod);
            method_setImplementation(existsMethod, (IMP)my_fileExistsAtPath);
        }
        SEL contentsSel = @selector(contentsOfDirectoryAtPath:error:);
        Method contentsMethod = class_getInstanceMethod(fmClass, contentsSel);
        if (contentsMethod) {
            orig_contentsOfDirectoryAtPathError = (NSArray*(*)(id,SEL,NSString*,NSError**))method_getImplementation(contentsMethod);
            method_setImplementation(contentsMethod, (IMP)my_contentsOfDirectoryAtPathError);
        }
    }
}

// ============================================================================
// fishhook bindings (includes dyld_get_image_name)
// ============================================================================
void fishhook_bindings() {
    struct rebinding bindings[] = {
        {"sysctl", (void *)my_sysctl, (void **)&orig_sysctl},
        {"sysctlbyname", (void *)my_sysctlbyname, (void **)&orig_sysctlbyname},
        {"dlopen", (void *)my_dlopen, (void **)&orig_dlopen},
        {"dlsym", (void *)my_dlsym, (void **)&orig_dlsym},
        {"task_for_pid", (void *)my_task_for_pid, (void **)&orig_task_for_pid},
        {"vm_read_overwrite", (void *)my_vm_read_overwrite, (void **)&orig_vm_read_overwrite},
        {"vm_write", (void *)my_vm_write, (void **)&orig_vm_write},
        {"vm_protect", (void *)my_vm_protect, (void **)&orig_vm_protect},
        {"mach_vm_protect", (void *)my_mach_vm_protect, (void **)&orig_mach_vm_protect},
        {"dyld_get_image_name", (void *)my_dyld_get_image_name, (void **)&orig_dyld_get_image_name},
        {"SecItemCopyMatching", (void *)my_SecItemCopyMatching, (void **)&orig_SecItemCopyMatching},
        {"SecItemAdd", (void *)my_SecItemAdd, (void **)&orig_SecItemAdd},
        {"SecItemUpdate", (void *)my_SecItemUpdate, (void **)&orig_SecItemUpdate},
        {"SecItemDelete", (void *)my_SecItemDelete, (void **)&orig_SecItemDelete},
        {"SecKeyCreateRandomKey", (void *)my_SecKeyCreateRandomKey, (void **)&orig_SecKeyCreateRandomKey},
        {"SecKeyCopyPublicKey", (void *)my_SecKeyCopyPublicKey, (void **)&orig_SecKeyCopyPublicKey},
        {"SecKeyCreateSignature", (void *)my_SecKeyCreateSignature, (void **)&orig_SecKeyCreateSignature},
        {"SecKeyVerifySignature", (void *)my_SecKeyVerifySignature, (void **)&orig_SecKeyVerifySignature},
        {"CCCrypt", (void *)my_CCCrypt, (void **)&orig_CCCrypt},
        {"RSA_verify", (void *)my_RSA_verify, (void **)&orig_RSA_verify},
        {"RSA_sign", (void *)my_RSA_sign, (void **)&orig_RSA_sign},
        {"EVP_PKEY_verify", (void *)my_EVP_PKEY_verify, (void **)&orig_EVP_PKEY_verify},
        {"X509_verify_cert", (void *)my_X509_verify_cert, (void **)&orig_X509_verify_cert},
        {"X509_check_private_key", (void *)my_X509_check_private_key, (void **)&orig_X509_check_private_key},
        {"PEM_read_bio_PrivateKey", (void *)my_PEM_read_bio_PrivateKey, (void **)&orig_PEM_read_bio_PrivateKey},
        {"SSL_CTX_use_PrivateKey_file", (void *)my_SSL_CTX_use_PrivateKey_file, (void **)&orig_SSL_CTX_use_PrivateKey_file},
        {"SSL_CTX_check_private_key", (void *)my_SSL_CTX_check_private_key, (void **)&orig_SSL_CTX_check_private_key},
        {"SSL_CTX_load_verify_locations", (void *)my_SSL_CTX_load_verify_locations, (void **)&orig_SSL_CTX_load_verify_locations},
    };
    rebind_symbols(bindings, sizeof(bindings)/sizeof(bindings[0]));
}

// ============================================================================
// __interpose for printf
// ============================================================================
typedef struct interpose_s {
    void *new_func;
    void *orig_func;
} interpose_t;

#define INTERPOSE(new, orig) \
    __attribute__((used)) static const interpose_t interpose_##new \
    __attribute__((section("__DATA,__interpose"))) = { (void *)new, (void *)orig };

static int my_printf(const char *format, ...);
INTERPOSE(my_printf, printf)

static int my_printf(const char *format, ...) {
    if (strstr(format, "debug") || strstr(format, "jailbreak") || strstr(format, "substrate")) {
        return 0;
    }
    va_list args;
    va_start(args, format);
    int ret = vprintf(format, args);
    va_end(args);
    return ret;
}

// ============================================================================
// Modified security checks – they now report clean environment and never exit
// ============================================================================
int is_simulator() {
#if TARGET_IPHONE_SIMULATOR
    return 1;
#else
    struct utsname systemInfo;
    uname(&systemInfo);
    if (strcmp(systemInfo.machine, "x86_64") == 0 || strcmp(systemInfo.machine, "i386") == 0)
        return 1;
    return 0;
#endif
}

int is_jailbroken_paths() { return 0; } // always return clean
int is_cydia_installed() { return 0; }
int is_dyld_hijacked() { return 0; }
int is_debugger_attached() { return 0; }
int ptrace_deny_attach() { return 0; }
int is_substrate_loaded() { return 0; }
int is_ssh_running() { return 0; }
int is_apt_installed() { return 0; }
int is_frida_installed() { return 0; }
int is_debugserver_installed() { return 0; }
int check_provisioning() { return 0; }
int check_env() { return 0; }
int check_ppid() { return 0; }
int is_frida_loaded() { return 0; }

void perform_security_checks() {
    // All checks overridden to return safe values – no exit
    // Just a dummy function that does nothing harmful
}

// ============================================================================
// Constructor – runs on load
// ============================================================================
__attribute__((constructor))
void init_hook() {
    srand((unsigned int)time(NULL));
    load_real_ptrace();
    fishhook_bindings();        // hook low-level C functions
    swizzle_objc_methods();     // hook Objective-C methods
    
    // No exit, no delays – the app remains fully functional
    // Optionally show SwiftUI bridge (keep original behavior)
    dispatch_async(dispatch_get_main_queue(), ^{
        Class bridgeClass = NSClassFromString(@"BlackUIBridge");
        if (bridgeClass) {
            SEL showSel = NSSelectorFromString(@"showProtectionUI");
            if ([bridgeClass respondsToSelector:showSel]) {
                #pragma clang diagnostic push
                #pragma clang diagnostic ignored "-Warc-performSelector-leaks"
                [bridgeClass performSelector:showSel];
                #pragma clang diagnostic pop
            }
        }
    });
}
