// hook.mm - Optimized and Modernized Version
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
#import <errno.h>
#import <dispatch/dispatch.h>
#import <Foundation/Foundation.h>

#if TARGET_OS_IPHONE
#import <objc/runtime.h>
#import <objc/message.h>
#import <LocalAuthentication/LocalAuthentication.h>
#endif

#include "fishhook.h"

// ============================================================================
#pragma mark - Globals & Ptrace
// ============================================================================

#define PT_DENY_ATTACH 31
typedef int (*ptrace_ptr_t)(int, pid_t, caddr_t, int);
static ptrace_ptr_t real_ptrace = NULL;

static void load_real_ptrace(void) {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        real_ptrace = (ptrace_ptr_t)dlsym(RTLD_DEFAULT, "ptrace");
    });
}

// ============================================================================
#pragma mark - Original Function Pointers
// ============================================================================

static int (*orig_sysctl)(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen);
static int (*orig_sysctlbyname)(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen);
static void* (*orig_dlopen)(const char *path, int mode);
static void* (*orig_dlsym)(void *handle, const char *symbol);
static int (*orig_task_for_pid)(mach_port_t target_tport, int pid, mach_port_t *tn);
static int (*orig_vm_read_overwrite)(vm_map_t target_task, vm_address_t address, vm_size_t size, vm_address_t data, vm_size_t *outsize);
static int (*orig_vm_write)(vm_map_t target_task, vm_address_t address, vm_offset_t data, mach_msg_type_number_t dataCnt);
static int (*orig_vm_protect)(vm_map_t target_task, vm_address_t address, vm_size_t size, boolean_t set_max, vm_protect_t new_protection);
static int (*orig_mach_vm_protect)(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, boolean_t set_max, vm_protect_t new_protection);

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

// CommonCrypto & OpenSSL
static CCCryptorStatus (*orig_CCCrypt)(CCOperation op, CCAlgorithm alg, CCOptions options, const void *key, size_t keyLength, const void *iv, const void *dataIn, size_t dataInLength, void *dataOut, size_t dataOutAvailable, size_t *dataOutMoved);
static int (*orig_RSA_verify)(int type, const unsigned char *m, unsigned int m_len, const unsigned char *sig, unsigned int sig_len, void *rsa);
static int (*orig_RSA_sign)(int type, const unsigned char *m, unsigned int m_len, unsigned char *sig, unsigned int *sig_len, void *rsa);
static int (*orig_EVP_PKEY_verify)(void *ctx, const unsigned char *sig, size_t sig_len, const unsigned char *tbs, size_t tbs_len);
static int (*orig_X509_verify_cert)(void *ctx);
static int (*orig_X509_check_private_key)(void *x509, void *pkey);
static void* (*orig_PEM_read_bio_PrivateKey)(void *bp, void **x, void *cb, void *u);
static int (*orig_SSL_CTX_use_PrivateKey_file)(void *ctx, const char *file, int type);
static int (*orig_SSL_CTX_check_private_key)(void *ctx);
static int (*orig_SSL_CTX_load_verify_locations)(void *ctx, const char *CAfile, const char *CApath);

// OS & Environment
static uint32_t (*orig__dyld_image_count)(void);
static const char* (*orig__dyld_get_image_name)(uint32_t image_index);
static const struct mach_header* (*orig__dyld_get_image_header)(uint32_t image_index);
static intptr_t (*orig__dyld_get_image_vmaddr_slide)(uint32_t image_index);
static int (*orig_access)(const char *path, int mode);
static int (*orig_stat)(const char *path, struct stat *buf);
static int (*orig_lstat)(const char *path, struct stat *buf);
static int (*orig_getpid)(void);
static int (*orig_dladdr)(const void *addr, Dl_info *info);
static int (*orig_task_info)(task_name_t target_task, task_flavor_t flavor, task_info_t task_info_out, mach_msg_type_number_t *task_info_outCnt);
static kern_return_t (*orig_vm_region_recurse_64)(vm_map_t target_task, vm_address_t *address, vm_size_t *size, natural_t *nesting_depth, vm_region_recurse_info_t info, mach_msg_type_number_t *infoCnt);
static kern_return_t (*orig_vm_region_64)(vm_map_t target_task, vm_address_t *address, vm_size_t *size, vm_region_flavor_t flavor, vm_region_info_t info, mach_msg_type_number_t *infoCnt, mach_port_t *object_name);
static kern_return_t (*orig_mach_vm_region_recurse)(vm_map_t target_task, mach_vm_address_t *address, mach_vm_size_t *size, natural_t *nesting_depth, vm_region_recurse_info_t info, mach_msg_type_number_t *infoCnt);
static char* (*orig_getenv)(const char *name);
static OSStatus (*orig_SecStaticCodeCheckValidity)(SecStaticCodeRef staticCode, SecCSFlags flags, SecRequirementRef requirement);

// ============================================================================
#pragma mark - Shared Utilities
// ============================================================================

// Static helper to prevent repetitive array initialization during FS operations
static inline bool is_sensitive_path(const char *path) {
    if (!path) return false;
    static const char *sensitive[] = {
        "Cydia", "MobileSubstrate", "frida", "cydia", 
        "Substrate", "checkra1n", "jailbreak", "apt", 
        "ssh", "debugserver", "proc"
    };
    static const int sensitive_count = sizeof(sensitive) / sizeof(sensitive[0]);
    
    for (int i = 0; i < sensitive_count; i++) {
        if (strstr(path, sensitive[i])) return true;
    }
    return false;
}

// ============================================================================
#pragma mark - Replacement Hooks
// ============================================================================

static int my_ptrace(int request, pid_t pid, caddr_t addr, int data) {
    if (request == PT_DENY_ATTACH) return 0;
    load_real_ptrace();
    return real_ptrace ? real_ptrace(request, pid, addr, data) : 0;
}

static int my_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    int ret = orig_sysctl ? orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen) : 0;
    if (ret == 0 && oldp && namelen == 4 && name[0] == CTL_KERN && name[1] == KERN_PROC && name[2] == KERN_PROC_PID) {
        struct kinfo_proc *kp = (struct kinfo_proc *)oldp;
        kp->kp_proc.p_flag &= ~P_TRACED;
    }
    return ret;
}

static int my_sysctlbyname(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    if (oldp && oldlenp && (strstr(name, "debug") || strstr(name, "proc"))) {
        memset(oldp, 0, *oldlenp);
        return 0;
    }
    return orig_sysctlbyname ? orig_sysctlbyname(name, oldp, oldlenp, newp, newlen) : 0;
}

static void* my_dlopen(const char *path, int mode) {
    if (path && (strstr(path, "frida") || strstr(path, "substrate") || strstr(path, "cydia"))) return NULL;
    return orig_dlopen ? orig_dlopen(path, mode) : NULL;
}

static void* my_dlsym(void *handle, const char *symbol) {
    if (symbol && (strstr(symbol, "ptrace") || strstr(symbol, "sysctl") || strstr(symbol, "task_for_pid") ||
                   strstr(symbol, "vm_read") || strstr(symbol, "dyld_image") || strstr(symbol, "getenv"))) return NULL;
    return orig_dlsym ? orig_dlsym(handle, symbol) : NULL;
}

static int my_task_for_pid(mach_port_t target_tport, int pid, mach_port_t *tn) { return KERN_FAILURE; }
static int my_vm_read_overwrite(vm_map_t target_task, vm_address_t address, vm_size_t size, vm_address_t data, vm_size_t *outsize) { return KERN_FAILURE; }
static int my_vm_write(vm_map_t target_task, vm_address_t address, vm_offset_t data, mach_msg_type_number_t dataCnt) { return KERN_FAILURE; }
static int my_vm_protect(vm_map_t target_task, vm_address_t address, vm_size_t size, boolean_t set_max, vm_protect_t new_protection) { return KERN_SUCCESS; }
static int my_mach_vm_protect(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, boolean_t set_max, vm_protect_t new_protection) { return KERN_SUCCESS; }

// Keychain
static OSStatus my_SecItemCopyMatching(CFDictionaryRef query, CFTypeRef *result) { return errSecItemNotFound; }
static OSStatus my_SecItemAdd(CFDictionaryRef attributes, CFTypeRef *result) { return errSecDuplicateItem; }
static OSStatus my_SecItemUpdate(CFDictionaryRef query, CFDictionaryRef attributesToUpdate) { return errSecItemNotFound; }
static OSStatus my_SecItemDelete(CFDictionaryRef query) { return errSecSuccess; }

// SecKey
static SecKeyRef my_SecKeyCreateRandomKey(CFDictionaryRef parameters, CFErrorRef *error) { return NULL; }
static SecKeyRef my_SecKeyCopyPublicKey(SecKeyRef key) { return NULL; }
static CFDataRef my_SecKeyCreateSignature(SecKeyRef key, SecKeyAlgorithm algorithm, CFDataRef dataToSign, CFErrorRef *error) {
    const char *fake = "fake_signature";
    return CFDataCreate(NULL, (const UInt8*)fake, (CFIndex)strlen(fake));
}
static Boolean my_SecKeyVerifySignature(SecKeyRef key, SecKeyAlgorithm algorithm, CFDataRef dataToSign, CFDataRef signature, CFErrorRef *error) { return true; }

// CommonCrypto
static CCCryptorStatus my_CCCrypt(CCOperation op, CCAlgorithm alg, CCOptions options, const void *key, size_t keyLength, const void *iv, const void *dataIn, size_t dataInLength, void *dataOut, size_t dataOutAvailable, size_t *dataOutMoved) {
    if (!dataOut || !dataOutMoved) return kCCParamError;
    size_t bytes = dataInLength < dataOutAvailable ? dataInLength : dataOutAvailable;
    memcpy(dataOut, dataIn, bytes);
    *dataOutMoved = bytes;
    return bytes == dataInLength ? kCCSuccess : kCCBufferTooSmall;
}

// OpenSSL
static int my_RSA_verify(int type, const unsigned char *m, unsigned int m_len, const unsigned char *sig, unsigned int sig_len, void *rsa) { return 1; }
static int my_RSA_sign(int type, const unsigned char *m, unsigned int m_len, unsigned char *sig, unsigned int *sig_len, void *rsa) { return 0; }
static int my_EVP_PKEY_verify(void *ctx, const unsigned char *sig, size_t sig_len, const unsigned char *tbs, size_t tbs_len) { return 1; }
static int my_X509_verify_cert(void *ctx) { return 1; }
static int my_X509_check_private_key(void *x509, void *pkey) { return 1; }
static void* my_PEM_read_bio_PrivateKey(void *bp, void **x, void *cb, void *u) { return NULL; }
static int my_SSL_CTX_use_PrivateKey_file(void *ctx, const char *file, int type) { return 1; }
static int my_SSL_CTX_check_private_key(void *ctx) { return 1; }
static int my_SSL_CTX_load_verify_locations(void *ctx, const char *CAfile, const char *CApath) { return 1; }

// OS Checks
static uint32_t my__dyld_image_count(void) { return 0; }
static const char* my__dyld_get_image_name(uint32_t image_index) { return NULL; }
static const struct mach_header* my__dyld_get_image_header(uint32_t image_index) { return NULL; }
static intptr_t my__dyld_get_image_vmaddr_slide(uint32_t image_index) { return 0; }

static int my_access(const char *path, int mode) {
    if (is_sensitive_path(path)) { errno = ENOENT; return -1; }
    return orig_access ? orig_access(path, mode) : -1;
}

static int my_stat(const char *path, struct stat *buf) {
    if (is_sensitive_path(path)) { errno = ENOENT; return -1; }
    return orig_stat ? orig_stat(path, buf) : -1;
}

static int my_lstat(const char *path, struct stat *buf) {
    if (is_sensitive_path(path)) { errno = ENOENT; return -1; }
    return orig_lstat ? orig_lstat(path, buf) : -1;
}

static int my_getpid(void) { return orig_getpid ? orig_getpid() : getpid(); }
static int my_dladdr(const void *addr, Dl_info *info) { return 0; }
static int my_task_info(task_name_t target_task, task_flavor_t flavor, task_info_t task_info_out, mach_msg_type_number_t *task_info_outCnt) { return KERN_FAILURE; }
static kern_return_t my_vm_region_recurse_64(vm_map_t target_task, vm_address_t *address, vm_size_t *size, natural_t *nesting_depth, vm_region_recurse_info_t info, mach_msg_type_number_t *infoCnt) { return KERN_INVALID_ADDRESS; }
static kern_return_t my_vm_region_64(vm_map_t target_task, vm_address_t *address, vm_size_t *size, vm_region_flavor_t flavor, vm_region_info_t info, mach_msg_type_number_t *infoCnt, mach_port_t *object_name) { return KERN_INVALID_ADDRESS; }
static kern_return_t my_mach_vm_region_recurse(vm_map_t target_task, mach_vm_address_t *address, mach_vm_size_t *size, natural_t *nesting_depth, vm_region_recurse_info_t info, mach_msg_type_number_t *infoCnt) { return KERN_INVALID_ADDRESS; }

static char* my_getenv(const char *name) {
    if (name && (strcmp(name, "DYLD_INSERT_LIBRARIES") == 0 || strcmp(name, "DYLD_FORCE_FLAT_NAMESPACE") == 0 || strcmp(name, "DYLD_PRINT_TO_FILE") == 0)) return NULL;
    return orig_getenv ? orig_getenv(name) : NULL;
}

static OSStatus my_SecStaticCodeCheckValidity(SecStaticCodeRef staticCode, SecCSFlags flags, SecRequirementRef requirement) { return errSecSuccess; }

// ============================================================================
#pragma mark - Objective-C Swizzling
// ============================================================================

static id my_UIDevice_identifierForVendor(id self, SEL _cmd) {
    // Memory Optimization: Cache the forged UUID to mimic actual Apple API behavior.
    static NSUUID *fakeUUID = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        fakeUUID = [[NSUUID alloc] initWithUUIDString:@"00000000-0000-0000-0000-000000000000"];
    });
    return fakeUUID;
}

static void my_LAContext_evaluatePolicy(id self, SEL _cmd, LAPolicy policy, NSString *localizedReason, void(^reply)(BOOL success, NSError *error)) { 
    if (reply) reply(YES, nil); 
}

static BOOL my_LAContext_canEvaluatePolicy(id self, SEL _cmd, LAPolicy policy, NSError **error) { 
    return YES; 
}

static void swizzle_objc_methods() {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        Class deviceCls = objc_getClass("UIDevice");
        if (deviceCls) {
            SEL sel = @selector(identifierForVendor);
            Method m = class_getInstanceMethod(deviceCls, sel);
            if (m) {
                // Method replaced safely
                method_setImplementation(m, (IMP)my_UIDevice_identifierForVendor); 
            }
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
    });
}

// ============================================================================
#pragma mark - Fishhook Setup
// ============================================================================

static void fishhook_bindings() {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        struct rebinding bindings[] = {
            {"sysctl", my_sysctl, (void **)&orig_sysctl},
            {"sysctlbyname", my_sysctlbyname, (void **)&orig_sysctlbyname},
            {"dlopen", my_dlopen, (void **)&orig_dlopen},
            {"dlsym", my_dlsym, (void **)&orig_dlsym},
            {"task_for_pid", my_task_for_pid, (void **)&orig_task_for_pid},
            {"vm_read_overwrite", my_vm_read_overwrite, (void **)&orig_vm_read_overwrite},
            {"vm_write", my_vm_write, (void **)&orig_vm_write},
            {"vm_protect", my_vm_protect, (void **)&orig_vm_protect},
            {"mach_vm_protect", my_mach_vm_protect, (void **)&orig_mach_vm_protect},
            {"SecItemCopyMatching", my_SecItemCopyMatching, (void **)&orig_SecItemCopyMatching},
            {"SecItemAdd", my_SecItemAdd, (void **)&orig_SecItemAdd},
            {"SecItemUpdate", my_SecItemUpdate, (void **)&orig_SecItemUpdate},
            {"SecItemDelete", my_SecItemDelete, (void **)&orig_SecItemDelete},
            {"SecKeyCreateRandomKey", my_SecKeyCreateRandomKey, (void **)&orig_SecKeyCreateRandomKey},
            {"SecKeyCopyPublicKey", my_SecKeyCopyPublicKey, (void **)&orig_SecKeyCopyPublicKey},
            {"SecKeyCreateSignature", my_SecKeyCreateSignature, (void **)&orig_SecKeyCreateSignature},
            {"SecKeyVerifySignature", my_SecKeyVerifySignature, (void **)&orig_SecKeyVerifySignature},
            {"CCCrypt", my_CCCrypt, (void **)&orig_CCCrypt},
            {"RSA_verify", my_RSA_verify, (void **)&orig_RSA_verify},
            {"RSA_sign", my_RSA_sign, (void **)&orig_RSA_sign},
            {"EVP_PKEY_verify", my_EVP_PKEY_verify, (void **)&orig_EVP_PKEY_verify},
            {"X509_verify_cert", my_X509_verify_cert, (void **)&orig_X509_verify_cert},
            {"X509_check_private_key", my_X509_check_private_key, (void **)&orig_X509_check_private_key},
            {"PEM_read_bio_PrivateKey", my_PEM_read_bio_PrivateKey, (void **)&orig_PEM_read_bio_PrivateKey},
            {"SSL_CTX_use_PrivateKey_file", my_SSL_CTX_use_PrivateKey_file, (void **)&orig_SSL_CTX_use_PrivateKey_file},
            {"SSL_CTX_check_private_key", my_SSL_CTX_check_private_key, (void **)&orig_SSL_CTX_check_private_key},
            {"SSL_CTX_load_verify_locations", my_SSL_CTX_load_verify_locations, (void **)&orig_SSL_CTX_load_verify_locations},
            {"_dyld_image_count", my__dyld_image_count, (void **)&orig__dyld_image_count},
            {"_dyld_get_image_name", my__dyld_get_image_name, (void **)&orig__dyld_get_image_name},
            {"_dyld_get_image_header", my__dyld_get_image_header, (void **)&orig__dyld_get_image_header},
            {"_dyld_get_image_vmaddr_slide", my__dyld_get_image_vmaddr_slide, (void **)&orig__dyld_get_image_vmaddr_slide},
            {"access", my_access, (void **)&orig_access},
            {"stat", my_stat, (void **)&orig_stat},
            {"lstat", my_lstat, (void **)&orig_lstat},
            {"getpid", my_getpid, (void **)&orig_getpid},
            {"dladdr", my_dladdr, (void **)&orig_dladdr},
            {"task_info", my_task_info, (void **)&orig_task_info},
            {"vm_region_recurse_64", my_vm_region_recurse_64, (void **)&orig_vm_region_recurse_64},
            {"vm_region_64", my_vm_region_64, (void **)&orig_vm_region_64},
            {"mach_vm_region_recurse", my_mach_vm_region_recurse, (void **)&orig_mach_vm_region_recurse},
            {"getenv", my_getenv, (void **)&orig_getenv},
            {"SecStaticCodeCheckValidity", my_SecStaticCodeCheckValidity, (void **)&orig_SecStaticCodeCheckValidity},
        };
        rebind_symbols(bindings, sizeof(bindings)/sizeof(bindings[0]));
    });
}

// ============================================================================
#pragma mark - Security Checks (Maintained for Backward Compatibility)
// ============================================================================

int is_simulator() {
#if TARGET_IPHONE_SIMULATOR
    return 1;
#else
    struct utsname systemInfo;
    uname(&systemInfo);
    return (strcmp(systemInfo.machine, "x86_64") == 0 || strcmp(systemInfo.machine, "i386") == 0);
#endif
}

int is_jailbroken_paths() { return 0; }
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
void perform_security_checks() { /* Intentionally maintained empty */ }

// ============================================================================
#pragma mark - Initialization
// ============================================================================

__attribute__((constructor))
static void init_hook() {
    srand((unsigned int)time(NULL));
    
    // Use modern QoS dispatch class over deprecated priority macros.
    dispatch_queue_t queue = dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0);
    
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(20.0 * NSEC_PER_SEC)), queue, ^{
        load_real_ptrace();
        perform_security_checks();
        fishhook_bindings();
        swizzle_objc_methods();
        
        dispatch_async(dispatch_get_main_queue(), ^{
            Class bridgeClass = NSClassFromString(@"BlackUIBridge");
            if (bridgeClass) {
                SEL showSel = NSSelectorFromString(@"showProtectionUI");
                if ([bridgeClass respondsToSelector:showSel]) {
                    #pragma clang diagnostic push
                    #pragma clang diagnostic ignored "-Warc-performSelector-leaks"
                    [bridgeClass performSelector:showSel];
                    #pragma clang diagnostic pop
                    printf("[SEC] Protection UI shown successfully.\n");
                } else {
                    printf("[SEC] Error: Method showProtectionUI not found.\n");
                }
            } else {
                printf("[SEC] Error: Swift Bridge Class 'BlackUIBridge' not found.\n");
            }
        });
    });
}
