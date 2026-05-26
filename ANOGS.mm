// ANOGS.mm (modified - no exit)
#import <stdio.h>
#import <string.h>
#import <unistd.h>
#import <stdlib.h>
#import <sys/stat.h>
#import <sys/sysctl.h>
#import <sys/utsname.h>
#import <dlfcn.h>
#import <mach/mach.h>
#import <mach/mach_vm.h>
#import <mach-o/dyld.h>
#import <TargetConditionals.h>
#import <sys/param.h>
#import <sys/mount.h>
#import <CommonCrypto/CommonCryptor.h>
#import <Security/Security.h>
#import <Security/SecTrust.h>
#import <Security/SecureTransport.h>
#import <time.h>
#import <dispatch/dispatch.h>

#if TARGET_OS_IPHONE
#import <objc/runtime.h>
#import <objc/message.h>
#import <LocalAuthentication/LocalAuthentication.h>
#endif

#include "fishhook.h"

// ============================================================================
// Global protection flag (default: OFF)
// ============================================================================
static bool is_protection_enabled = false;

// ============================================================================
// ptrace dynamic lookup
// ============================================================================
#define PT_DENY_ATTACH 31
typedef int (*ptrace_ptr_t)(int, pid_t, caddr_t, int);
static ptrace_ptr_t real_ptrace = NULL;
static void load_real_ptrace(void) {
    if (!real_ptrace) real_ptrace = (ptrace_ptr_t)dlsym(RTLD_DEFAULT, "ptrace");
}

// Forward declarations for OpenSSL
typedef struct rsa_st RSA;
typedef struct evp_pkey_st EVP_PKEY;
typedef struct evp_pkey_ctx_st EVP_PKEY_CTX;
typedef struct x509_st X509;
typedef struct X509_store_ctx_st X509_STORE_CTX;
typedef struct ssl_ctx_st SSL_CTX;
typedef struct bio_st BIO;
typedef int pem_password_cb(char *buf, int size, int rwflag, void *userdata);

// ============================================================================
// Original function pointers (same as before)
// ============================================================================
static int (*orig_sysctl)(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen);
static int (*orig_sysctlbyname)(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen);
static void* (*orig_dlopen)(const char *path, int mode);
static void* (*orig_dlsym)(void *handle, const char *symbol);
static int (*orig_task_for_pid)(mach_port_t target_tport, int pid, mach_port_t *tn);
static int (*orig_vm_read_overwrite)(vm_map_t target_task, vm_address_t address, vm_size_t size, vm_address_t data, vm_size_t *outsize);
static int (*orig_vm_write)(vm_map_t target_task, vm_address_t address, vm_offset_t data, mach_msg_type_number_t dataCnt);
static int (*orig_vm_protect)(vm_map_t target_task, vm_address_t address, vm_size_t size, boolean_t set_max, vm_prot_t new_protection);
static int (*orig_mach_vm_protect)(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, boolean_t set_max, vm_prot_t new_protection);
static OSStatus (*orig_SecItemCopyMatching)(CFDictionaryRef query, CFTypeRef *result);
static OSStatus (*orig_SecItemAdd)(CFDictionaryRef attributes, CFTypeRef *result);
static OSStatus (*orig_SecItemUpdate)(CFDictionaryRef query, CFDictionaryRef attributesToUpdate);
static OSStatus (*orig_SecItemDelete)(CFDictionaryRef query);
static SecKeyRef (*orig_SecKeyCreateRandomKey)(CFDictionaryRef parameters, CFErrorRef *error);
static SecKeyRef (*orig_SecKeyCopyPublicKey)(SecKeyRef key);
static CFDataRef (*orig_SecKeyCreateSignature)(SecKeyRef key, SecKeyAlgorithm algorithm, CFDataRef dataToSign, CFErrorRef *error);
static Boolean (*orig_SecKeyVerifySignature)(SecKeyRef key, SecKeyAlgorithm algorithm, CFDataRef dataToSign, CFDataRef signature, CFErrorRef *error);
static CCCryptorStatus (*orig_CCCrypt)(CCOperation op, CCAlgorithm alg, CCOptions options, const void *key, size_t keyLength, const void *iv, const void *dataIn, size_t dataInLength, void *dataOut, size_t dataOutAvailable, size_t *dataOutMoved);
static int (*orig_RSA_verify)(int type, const unsigned char *m, unsigned int m_len, const unsigned char *sig, unsigned int sig_len, RSA *rsa);
static int (*orig_RSA_sign)(int type, const unsigned char *m, unsigned int m_len, unsigned char *sig, unsigned int *sig_len, RSA *rsa);
static int (*orig_EVP_PKEY_verify)(EVP_PKEY_CTX *ctx, const unsigned char *sig, size_t sig_len, const unsigned char *tbs, size_t tbs_len);
static int (*orig_X509_verify_cert)(X509_STORE_CTX *ctx);
static int (*orig_X509_check_private_key)(X509 *x509, EVP_PKEY *pkey);
static EVP_PKEY* (*orig_PEM_read_bio_PrivateKey)(BIO *bp, EVP_PKEY **x, pem_password_cb *cb, void *u);
static int (*orig_SSL_CTX_use_PrivateKey_file)(SSL_CTX *ctx, const char *file, int type);
static int (*orig_SSL_CTX_check_private_key)(SSL_CTX *ctx);
static int (*orig_SSL_CTX_load_verify_locations)(SSL_CTX *ctx, const char *CAfile, const char *CApath);
static char* (*orig_getenv)(const char*);
static int (*orig_stat)(const char*, struct stat*);
static int (*orig_lstat)(const char*, struct stat*);
static int (*orig_fstat)(int, struct stat*);
static int (*orig_dladdr)(const void*, Dl_info*);
static uint32_t (*orig__dyld_image_count)(void);
static intptr_t (*orig__dyld_get_image_vmaddr_slide)(uint32_t);
static const char* (*orig__dyld_get_image_name)(uint32_t);
static const struct mach_header* (*orig__dyld_get_image_header)(uint32_t);
static kern_return_t (*orig_vm_read)(vm_map_t, vm_address_t, vm_size_t, vm_offset_t*, vm_size_t*);
static kern_return_t (*orig_vm_region_64)(vm_map_t, vm_address_t*, vm_size_t*, vm_region_flavor_t*, vm_region_info_t, mach_msg_type_number_t*, mach_port_t*);
static kern_return_t (*orig_vm_region_recurse_64)(vm_map_t, vm_address_t*, vm_size_t*, uint32_t*, vm_region_info_t, mach_msg_type_number_t*);
static kern_return_t (*orig_mach_vm_region_recurse)(vm_map_t, mach_vm_address_t*, mach_vm_size_t*, uint32_t*, vm_region_info_t, mach_msg_type_number_t*);
static void (*orig_SSLGetEnabledCiphers)(SSLContextRef, uint16_t*, size_t*);
static size_t (*orig_SSLGetNegotiatedCipher)(SSLContextRef);
static void (*orig_SSLGetNumberEnabledCiphers)(SSLContextRef, size_t*);
static void (*orig_SSLGetNumberSupportedCiphers)(SSLContextRef, size_t*);
static void (*orig_SSLGetSupportedCiphers)(SSLContextRef, uint16_t*, size_t*);
static CFAbsoluteTime (*orig_SecTrustGetVerifyTime)(SecTrustRef);

// ============================================================================
// Replacement functions (unchanged, respect flag)
// ============================================================================
static int my_ptrace(int request, pid_t pid, caddr_t addr, int data) {
    if (!is_protection_enabled) { load_real_ptrace(); return real_ptrace ? real_ptrace(request, pid, addr, data) : 0; }
    if (request == PT_DENY_ATTACH) return 0;
    load_real_ptrace();
    return real_ptrace ? real_ptrace(request, pid, addr, data) : 0;
}
static int my_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    int ret = orig_sysctl ? orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen) : 0;
    if (is_protection_enabled && ret == 0 && oldp && namelen == 4 && name[0] == CTL_KERN && name[1] == KERN_PROC && name[2] == KERN_PROC_PID)
        ((struct kinfo_proc *)oldp)->kp_proc.p_flag &= ~P_TRACED;
    return ret;
}
static int my_sysctlbyname(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    if (is_protection_enabled && oldp && oldlenp && (strstr(name, "debug") || strstr(name, "kern.proc"))) {
        memset(oldp, 0, *oldlenp);
        return 0;
    }
    return orig_sysctlbyname ? orig_sysctlbyname(name, oldp, oldlenp, newp, newlen) : 0;
}
static void* my_dlopen(const char *path, int mode) { return orig_dlopen ? orig_dlopen(path, mode) : NULL; }
static void* my_dlsym(void *handle, const char *symbol) {
    if (is_protection_enabled && symbol && (strstr(symbol, "ptrace") || strstr(symbol, "sysctl") || strstr(symbol, "task_for_pid") || strstr(symbol, "vm_read")))
        return NULL;
    return orig_dlsym ? orig_dlsym(handle, symbol) : NULL;
}
static int my_task_for_pid(mach_port_t t, int pid, mach_port_t *tn) { return is_protection_enabled ? KERN_FAILURE : (orig_task_for_pid ? orig_task_for_pid(t, pid, tn) : KERN_FAILURE); }
static int my_vm_read_overwrite(vm_map_t t, vm_address_t a, vm_size_t s, vm_address_t d, vm_size_t *o) { return is_protection_enabled ? KERN_FAILURE : (orig_vm_read_overwrite ? orig_vm_read_overwrite(t, a, s, d, o) : KERN_FAILURE); }
static int my_vm_write(vm_map_t t, vm_address_t a, vm_offset_t d, mach_msg_type_number_t c) { return is_protection_enabled ? KERN_FAILURE : (orig_vm_write ? orig_vm_write(t, a, d, c) : KERN_FAILURE); }
static int my_vm_protect(vm_map_t t, vm_address_t a, vm_size_t s, boolean_t m, vm_prot_t p) { return orig_vm_protect ? orig_vm_protect(t, a, s, m, p) : KERN_SUCCESS; }
static int my_mach_vm_protect(vm_map_t t, mach_vm_address_t a, mach_vm_size_t s, boolean_t m, vm_prot_t p) { return orig_mach_vm_protect ? orig_mach_vm_protect(t, a, s, m, p) : KERN_SUCCESS; }
static OSStatus my_SecItemCopyMatching(CFDictionaryRef q, CFTypeRef *r) { return (is_protection_enabled || !orig_SecItemCopyMatching) ? errSecItemNotFound : orig_SecItemCopyMatching(q, r); }
static OSStatus my_SecItemAdd(CFDictionaryRef a, CFTypeRef *r) { return (is_protection_enabled || !orig_SecItemAdd) ? errSecDuplicateItem : orig_SecItemAdd(a, r); }
static OSStatus my_SecItemUpdate(CFDictionaryRef q, CFDictionaryRef u) { return (is_protection_enabled || !orig_SecItemUpdate) ? errSecItemNotFound : orig_SecItemUpdate(q, u); }
static OSStatus my_SecItemDelete(CFDictionaryRef q) { return (is_protection_enabled || !orig_SecItemDelete) ? errSecSuccess : orig_SecItemDelete(q); }
static SecKeyRef my_SecKeyCreateRandomKey(CFDictionaryRef p, CFErrorRef *e) { return (is_protection_enabled || !orig_SecKeyCreateRandomKey) ? NULL : orig_SecKeyCreateRandomKey(p, e); }
static SecKeyRef my_SecKeyCopyPublicKey(SecKeyRef k) { return (is_protection_enabled || !orig_SecKeyCopyPublicKey) ? NULL : orig_SecKeyCopyPublicKey(k); }
static CFDataRef my_SecKeyCreateSignature(SecKeyRef k, SecKeyAlgorithm a, CFDataRef d, CFErrorRef *e) {
    if (!is_protection_enabled && orig_SecKeyCreateSignature) return orig_SecKeyCreateSignature(k, a, d, e);
    return CFDataCreate(NULL, (const UInt8*)"fake_signature", 14);
}
static Boolean my_SecKeyVerifySignature(SecKeyRef k, SecKeyAlgorithm a, CFDataRef d, CFDataRef s, CFErrorRef *e) {
    if (!is_protection_enabled && orig_SecKeyVerifySignature) return orig_SecKeyVerifySignature(k, a, d, s, e);
    return true;
}
static CCCryptorStatus my_CCCrypt(CCOperation op, CCAlgorithm alg, CCOptions opt, const void *key, size_t klen, const void *iv, const void *in, size_t inLen, void *out, size_t outAvail, size_t *moved) {
    if (!is_protection_enabled && orig_CCCrypt) return orig_CCCrypt(op, alg, opt, key, klen, iv, in, inLen, out, outAvail, moved);
    if (!out || !moved) return kCCParamError;
    size_t bytes = (inLen < outAvail) ? inLen : outAvail;
    memcpy(out, in, bytes);
    *moved = bytes;
    return (bytes == inLen) ? kCCSuccess : kCCBufferTooSmall;
}
static int my_RSA_verify(int t, const unsigned char *m, unsigned int ml, const unsigned char *s, unsigned int sl, RSA *r) { return (!is_protection_enabled && orig_RSA_verify) ? orig_RSA_verify(t, m, ml, s, sl, r) : 1; }
static int my_RSA_sign(int t, const unsigned char *m, unsigned int ml, unsigned char *s, unsigned int *sl, RSA *r) { if (!is_protection_enabled && orig_RSA_sign) return orig_RSA_sign(t, m, ml, s, sl, r); if (sl) *sl = 0; return 0; }
static int my_EVP_PKEY_verify(EVP_PKEY_CTX *c, const unsigned char *s, size_t sl, const unsigned char *t, size_t tl) { return (!is_protection_enabled && orig_EVP_PKEY_verify) ? orig_EVP_PKEY_verify(c, s, sl, t, tl) : 1; }
static int my_X509_verify_cert(X509_STORE_CTX *c) { return (!is_protection_enabled && orig_X509_verify_cert) ? orig_X509_verify_cert(c) : 1; }
static int my_X509_check_private_key(X509 *x, EVP_PKEY *p) { return (!is_protection_enabled && orig_X509_check_private_key) ? orig_X509_check_private_key(x, p) : 1; }
static EVP_PKEY* my_PEM_read_bio_PrivateKey(BIO *b, EVP_PKEY **x, pem_password_cb *c, void *u) { return (!is_protection_enabled && orig_PEM_read_bio_PrivateKey) ? orig_PEM_read_bio_PrivateKey(b, x, c, u) : NULL; }
static int my_SSL_CTX_use_PrivateKey_file(SSL_CTX *c, const char *f, int t) { return (!is_protection_enabled && orig_SSL_CTX_use_PrivateKey_file) ? orig_SSL_CTX_use_PrivateKey_file(c, f, t) : 1; }
static int my_SSL_CTX_check_private_key(SSL_CTX *c) { return (!is_protection_enabled && orig_SSL_CTX_check_private_key) ? orig_SSL_CTX_check_private_key(c) : 1; }
static int my_SSL_CTX_load_verify_locations(SSL_CTX *c, const char *ca, const char *cp) { return (!is_protection_enabled && orig_SSL_CTX_load_verify_locations) ? orig_SSL_CTX_load_verify_locations(c, ca, cp) : 1; }
static char* my_getenv(const char *name) {
    if (is_protection_enabled && name && (strstr(name, "DYLD_") || strstr(name, "CFNETWORK_") || strstr(name, "OBJC_DISABLE"))) return NULL;
    return orig_getenv ? orig_getenv(name) : NULL;
}
static int my_stat(const char *path, struct stat *buf) {
    if (is_protection_enabled && path && (strstr(path, "/Applications/Cydia.app") || strstr(path, "/bin/bash") || strstr(path, "/usr/sbin/sshd") || strstr(path, "/etc/apt") || strstr(path, "/var/checkra1n.dmg"))) return -1;
    return orig_stat ? orig_stat(path, buf) : -1;
}
static int my_lstat(const char *path, struct stat *buf) {
    if (is_protection_enabled && path && (strstr(path, "/Applications/Cydia.app") || strstr(path, "/bin/bash") || strstr(path, "/usr/sbin/sshd") || strstr(path, "/etc/apt"))) return -1;
    return orig_lstat ? orig_lstat(path, buf) : -1;
}
static int my_fstat(int fd, struct stat *buf) { return orig_fstat ? orig_fstat(fd, buf) : -1; }
static int my_dladdr(const void *addr, Dl_info *info) {
    if (is_protection_enabled) { if (info) memset(info, 0, sizeof(Dl_info)); return 0; }
    return orig_dladdr ? orig_dladdr(addr, info) : 0;
}
static uint32_t my__dyld_image_count(void) { return (!is_protection_enabled && orig__dyld_image_count) ? orig__dyld_image_count() : 0; }
static intptr_t my__dyld_get_image_vmaddr_slide(uint32_t i) { return (!is_protection_enabled && orig__dyld_get_image_vmaddr_slide) ? orig__dyld_get_image_vmaddr_slide(i) : 0; }
static const char* my__dyld_get_image_name(uint32_t i) { return (!is_protection_enabled && orig__dyld_get_image_name) ? orig__dyld_get_image_name(i) : NULL; }
static const struct mach_header* my__dyld_get_image_header(uint32_t i) { return (!is_protection_enabled && orig__dyld_get_image_header) ? orig__dyld_get_image_header(i) : NULL; }
static kern_return_t my_vm_read(vm_map_t t, vm_address_t a, vm_size_t s, vm_offset_t *d, vm_size_t *o) { return (!is_protection_enabled && orig_vm_read) ? orig_vm_read(t, a, s, d, o) : KERN_FAILURE; }
static kern_return_t my_vm_region_64(vm_map_t t, vm_address_t *a, vm_size_t *s, vm_region_flavor_t *f, vm_region_info_t i, mach_msg_type_number_t *c, mach_port_t *o) { return (!is_protection_enabled && orig_vm_region_64) ? orig_vm_region_64(t, a, s, f, i, c, o) : KERN_INVALID_ADDRESS; }
static kern_return_t my_vm_region_recurse_64(vm_map_t t, vm_address_t *a, vm_size_t *s, uint32_t *d, vm_region_info_t i, mach_msg_type_number_t *c) { return (!is_protection_enabled && orig_vm_region_recurse_64) ? orig_vm_region_recurse_64(t, a, s, d, i, c) : KERN_INVALID_ADDRESS; }
static kern_return_t my_mach_vm_region_recurse(vm_map_t t, mach_vm_address_t *a, mach_vm_size_t *s, uint32_t *d, vm_region_info_t i, mach_msg_type_number_t *c) { return (!is_protection_enabled && orig_mach_vm_region_recurse) ? orig_mach_vm_region_recurse(t, a, s, d, i, c) : KERN_INVALID_ADDRESS; }
static void my_SSLGetEnabledCiphers(SSLContextRef c, uint16_t *cip, size_t *num) { if (!is_protection_enabled && orig_SSLGetEnabledCiphers) orig_SSLGetEnabledCiphers(c, cip, num); else if (num) *num = 0; }
static size_t my_SSLGetNegotiatedCipher(SSLContextRef c) { return (!is_protection_enabled && orig_SSLGetNegotiatedCipher) ? orig_SSLGetNegotiatedCipher(c) : 0; }
static void my_SSLGetNumberEnabledCiphers(SSLContextRef c, size_t *num) { if (!is_protection_enabled && orig_SSLGetNumberEnabledCiphers) orig_SSLGetNumberEnabledCiphers(c, num); else if (num) *num = 0; }
static void my_SSLGetNumberSupportedCiphers(SSLContextRef c, size_t *num) { if (!is_protection_enabled && orig_SSLGetNumberSupportedCiphers) orig_SSLGetNumberSupportedCiphers(c, num); else if (num) *num = 0; }
static void my_SSLGetSupportedCiphers(SSLContextRef c, uint16_t *cip, size_t *num) { if (!is_protection_enabled && orig_SSLGetSupportedCiphers) orig_SSLGetSupportedCiphers(c, cip, num); else if (num) *num = 0; }
static CFAbsoluteTime my_SecTrustGetVerifyTime(SecTrustRef t) { return (!is_protection_enabled && orig_SecTrustGetVerifyTime) ? orig_SecTrustGetVerifyTime(t) : CFAbsoluteTimeGetCurrent(); }

// ============================================================================
// Objective-C swizzling (respects flag)
// ============================================================================
static IMP orig_UIDevice_identifierForVendor;
static id my_UIDevice_identifierForVendor(id self, SEL _cmd) {
    if (!is_protection_enabled && orig_UIDevice_identifierForVendor)
        return ((id (*)(id, SEL))orig_UIDevice_identifierForVendor)(self, _cmd);
    return [[NSUUID alloc] initWithUUIDString:@"00000000-0000-0000-0000-000000000000"];
}
static void my_LAContext_evaluatePolicy(id self, SEL _cmd, LAPolicy policy, NSString *reason, void(^reply)(BOOL, NSError*)) { if (reply) reply(YES, nil); }
static BOOL my_LAContext_canEvaluatePolicy(id self, SEL _cmd, LAPolicy policy, NSError **error) { return YES; }

void swizzle_objc_methods() {
    Class deviceCls = objc_getClass("UIDevice");
    if (deviceCls) {
        Method m = class_getInstanceMethod(deviceCls, @selector(identifierForVendor));
        if (m) { orig_UIDevice_identifierForVendor = method_getImplementation(m); method_setImplementation(m, (IMP)my_UIDevice_identifierForVendor); }
    }
    Class laContextCls = objc_getClass("LAContext");
    if (laContextCls) {
        Method m1 = class_getInstanceMethod(laContextCls, @selector(evaluatePolicy:localizedReason:reply:));
        if (m1) method_setImplementation(m1, (IMP)my_LAContext_evaluatePolicy);
        Method m2 = class_getInstanceMethod(laContextCls, @selector(canEvaluatePolicy:error:));
        if (m2) method_setImplementation(m2, (IMP)my_LAContext_canEvaluatePolicy);
    }
}

// ============================================================================
// Security checks – no exit, only log if needed (or ignore)
// ============================================================================
static int is_jailbroken_paths() {
    const char *paths[] = {"/Applications/Cydia.app", "/bin/bash", "/usr/sbin/sshd", "/etc/apt", "/var/checkra1n.dmg", NULL};
    for (int i = 0; paths[i]; i++) if (access(paths[i], F_OK) == 0) return 1;
    return 0;
}
static int is_debugger_attached() {
    int name[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()};
    struct kinfo_proc info;
    size_t sz = sizeof(info);
    if (sysctl(name, 4, &info, &sz, NULL, 0) == -1) return 0;
    return (info.kp_proc.p_flag & P_TRACED) != 0;
}
static int is_frida_loaded() { return dlopen("frida-agent.dylib", RTLD_NOLOAD) != NULL; }

void perform_security_checks() {
    if (!is_protection_enabled) return;
    // No exit anywhere – just ignore threats
    // Optionally log using NSLog (optional)
    /*
    if (is_jailbroken_paths()) NSLog(@"[ANOGS] Jailbreak detected but ignored");
    if (is_debugger_attached()) NSLog(@"[ANOGS] Debugger attached but ignored");
    if (is_frida_loaded()) NSLog(@"[ANOGS] Frida loaded but ignored");
    */
}

// ============================================================================
// Exported C function for Swift
// ============================================================================
extern "C" void set_protection_state(bool enabled) {
    bool was = is_protection_enabled;
    is_protection_enabled = enabled;
    if (enabled && !was) perform_security_checks();
}

// ============================================================================
// fishhook bindings (same as before)
// ============================================================================
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
        {"RSA_verify", (void*)my_RSA_verify, (void**)&orig_RSA_verify},
        {"RSA_sign", (void*)my_RSA_sign, (void**)&orig_RSA_sign},
        {"EVP_PKEY_verify", (void*)my_EVP_PKEY_verify, (void**)&orig_EVP_PKEY_verify},
        {"X509_verify_cert", (void*)my_X509_verify_cert, (void**)&orig_X509_verify_cert},
        {"X509_check_private_key", (void*)my_X509_check_private_key, (void**)&orig_X509_check_private_key},
        {"PEM_read_bio_PrivateKey", (void*)my_PEM_read_bio_PrivateKey, (void**)&orig_PEM_read_bio_PrivateKey},
        {"SSL_CTX_use_PrivateKey_file", (void*)my_SSL_CTX_use_PrivateKey_file, (void**)&orig_SSL_CTX_use_PrivateKey_file},
        {"SSL_CTX_check_private_key", (void*)my_SSL_CTX_check_private_key, (void**)&orig_SSL_CTX_check_private_key},
        {"SSL_CTX_load_verify_locations", (void*)my_SSL_CTX_load_verify_locations, (void**)&orig_SSL_CTX_load_verify_locations},
        {"getenv", (void*)my_getenv, (void**)&orig_getenv},
        {"stat", (void*)my_stat, (void**)&orig_stat},
        {"lstat", (void*)my_lstat, (void**)&orig_lstat},
        {"fstat", (void*)my_fstat, (void**)&orig_fstat},
        {"dladdr", (void*)my_dladdr, (void**)&orig_dladdr},
        {"_dyld_image_count", (void*)my__dyld_image_count, (void**)&orig__dyld_image_count},
        {"_dyld_get_image_vmaddr_slide", (void*)my__dyld_get_image_vmaddr_slide, (void**)&orig__dyld_get_image_vmaddr_slide},
        {"_dyld_get_image_name", (void*)my__dyld_get_image_name, (void**)&orig__dyld_get_image_name},
        {"_dyld_get_image_header", (void*)my__dyld_get_image_header, (void**)&orig__dyld_get_image_header},
        {"vm_read", (void*)my_vm_read, (void**)&orig_vm_read},
        {"vm_region_64", (void*)my_vm_region_64, (void**)&orig_vm_region_64},
        {"vm_region_recurse_64", (void*)my_vm_region_recurse_64, (void**)&orig_vm_region_recurse_64},
        {"mach_vm_region_recurse", (void*)my_mach_vm_region_recurse, (void**)&orig_mach_vm_region_recurse},
        {"SSLGetEnabledCiphers", (void*)my_SSLGetEnabledCiphers, (void**)&orig_SSLGetEnabledCiphers},
        {"SSLGetNegotiatedCipher", (void*)my_SSLGetNegotiatedCipher, (void**)&orig_SSLGetNegotiatedCipher},
        {"SSLGetNumberEnabledCiphers", (void*)my_SSLGetNumberEnabledCiphers, (void**)&orig_SSLGetNumberEnabledCiphers},
        {"SSLGetNumberSupportedCiphers", (void*)my_SSLGetNumberSupportedCiphers, (void**)&orig_SSLGetNumberSupportedCiphers},
        {"SSLGetSupportedCiphers", (void*)my_SSLGetSupportedCiphers, (void**)&orig_SSLGetSupportedCiphers},
        {"SecTrustGetVerifyTime", (void*)my_SecTrustGetVerifyTime, (void**)&orig_SecTrustGetVerifyTime},
    };
    rebind_symbols(bindings, sizeof(bindings)/sizeof(bindings[0]));
}

// ============================================================================
// Constructor – runs when dylib is loaded
// ============================================================================
__attribute__((constructor))
void init_hook() {
    load_real_ptrace();
    fishhook_bindings();
    swizzle_objc_methods();
    // protection is OFF by default
}
