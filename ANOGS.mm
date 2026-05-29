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

#if TARGET_OS_IPHONE
#import <objc/runtime.h>
#import <objc/message.h>
#import <LocalAuthentication/LocalAuthentication.h>
#endif

#include "fishhook.h"

// ptrace – not available in iOS SDK, use dynamic lookup
#define PT_DENY_ATTACH 31
typedef int (*ptrace_ptr_t)(int, pid_t, caddr_t, int);
static ptrace_ptr_t real_ptrace = NULL;
static void load_real_ptrace(void) {
    if (!real_ptrace) {
        real_ptrace = (ptrace_ptr_t)dlsym(RTLD_DEFAULT, "ptrace");
    }
}

// Forward declarations for OpenSSL types (no headers needed)
typedef struct rsa_st RSA;
typedef struct evp_pkey_st EVP_PKEY;
typedef struct evp_pkey_ctx_st EVP_PKEY_CTX;
typedef struct x509_st X509;
typedef struct X509_store_ctx_st X509_STORE_CTX;
typedef struct ssl_ctx_st SSL_CTX;
typedef struct bio_st BIO;
typedef int pem_password_cb(char *buf, int size, int rwflag, void *userdata);

// ============================================================================
// Original function pointers (existing)
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

// OpenSSL
static int (*orig_RSA_verify)(int type, const unsigned char *m, unsigned int m_len, const unsigned char *sig, unsigned int sig_len, RSA *rsa);
static int (*orig_RSA_sign)(int type, const unsigned char *m, unsigned int m_len, unsigned char *sig, unsigned int *sig_len, RSA *rsa);
static int (*orig_EVP_PKEY_verify)(EVP_PKEY_CTX *ctx, const unsigned char *sig, size_t sig_len, const unsigned char *tbs, size_t tbs_len);
static int (*orig_X509_verify_cert)(X509_STORE_CTX *ctx);
static int (*orig_X509_check_private_key)(X509 *x509, EVP_PKEY *pkey);
static EVP_PKEY* (*orig_PEM_read_bio_PrivateKey)(BIO *bp, EVP_PKEY **x, pem_password_cb *cb, void *u);
static int (*orig_SSL_CTX_use_PrivateKey_file)(SSL_CTX *ctx, const char *file, int type);
static int (*orig_SSL_CTX_check_private_key)(SSL_CTX *ctx);
static int (*orig_SSL_CTX_load_verify_locations)(SSL_CTX *ctx, const char *CAfile, const char *CApath);

// Environment checks
static bool (*orig_is_jb)(void);
static bool (*orig_ROOTED)(void);
static bool (*orig_DEBUGGER_ATTACHED)(void);
static bool (*orig_isDebuggerAttached)(void);
static bool (*orig_checkJailbreak)(void);
static bool (*orig_hasCydia)(void);
static bool (*orig_isJailbroken)(void);
static bool (*orig_amIBeingDebugged)(void);

// ============================================================================
// NEW: Security / Trust functions (added)
// ============================================================================
static OSStatus (*orig_SecTrustEvaluate)(SecTrustRef trust, SecTrustResultType *result);
static SecKeyRef (*orig_SecTrustCopyPublicKey)(SecTrustRef trust);
static SecCertificateRef (*orig_SecTrustGetCertificateAtIndex)(SecTrustRef trust, CFIndex ix);
static CFIndex (*orig_SecTrustGetCertificateCount)(SecTrustRef trust);
static OSStatus (*orig_SecTrustGetTrustResult)(SecTrustRef trust, SecTrustResultType *result);
static OSStatus (*orig_SecTrustSetAnchorCertificates)(SecTrustRef trust, CFArrayRef anchorCertificates);
static OSStatus (*orig_SecTrustSetAnchorCertificatesOnly)(SecTrustRef trust, Boolean anchorCertificatesOnly);
static OSStatus (*orig_SecTrustSetPolicies)(SecTrustRef trust, CFTypeRef policies);
static OSStatus (*orig_SecTrustSetVerifyDate)(SecTrustRef trust, CFDateRef verifyDate);
static CFDataRef (*orig_SecCertificateCopyData)(SecCertificateRef certificate);
static SecKeyRef (*orig_SecCertificateCopyKey)(SecCertificateRef certificate);
static SecCertificateRef (*orig_SecCertificateCreateWithData)(CFAllocatorRef allocator, CFDataRef data);
static SecPolicyRef (*orig_SecPolicyCreateSSL)(Boolean server, CFStringRef hostname);
static SecPolicyRef (*orig_SecPolicyCreateBasicX509)(void);
static SSLContextRef (*orig_SSLCreateContext)(CFAllocatorRef allocator, SSLProtocolSide protocolSide, SSLConnectionType connectionType);
static OSStatus (*orig_SSLHandshake)(SSLContextRef context);
static OSStatus (*orig_SSLSetSessionOption)(SSLContextRef context, SSLSessionOption option, Boolean value);
static OSStatus (*orig_SSLSetPeerDomainName)(SSLContextRef context, const char *peerName, size_t peerNameLen);
static OSStatus (*orig_SSLSetCertificate)(SSLContextRef context, CFArrayRef certs);
static CFDictionaryRef (*orig_CFNetworkCopySystemProxySettings)(void);
static CFArrayRef (*orig_CFNetworkCopyProxiesForURL)(CFURLRef url, CFDictionaryRef proxySettings);
static Boolean (*orig_SCNetworkReachabilityGetFlags)(SCNetworkReachabilityRef target, SCNetworkReachabilityFlags *flags);
static SCNetworkReachabilityRef (*orig_SCNetworkReachabilityCreateWithName)(CFAllocatorRef allocator, const char *name);
static SCNetworkReachabilityRef (*orig_SCNetworkReachabilityCreateWithAddress)(CFAllocatorRef allocator, const struct sockaddr *address);
static CFStringRef (*orig_kCFStreamSSLValidatesCertificateChain)(void);      // constants, not functions – ignore
static CFStringRef (*orig_kCFStreamSSLAllowsAnyRoot)(void);
static CFStringRef (*orig_kCFStreamSSLAllowsExpiredCertificates)(void);
static CFStringRef (*orig_kCFStreamSSLAllowsExpiredRoots)(void);
static CFStringRef (*orig_kCFStreamSSLCertificates)(void);
static CFStringRef (*orig_kCFStreamSSLPeerName)(void);
static CFTypeRef (*orig_CFStreamPropertySSLSettings)(void);                 // actually a constant, hook not needed

// ============================================================================
// Replacement functions (existing)
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
    if (oldp && oldlenp) {
        if (strstr(name, "debug") || strstr(name, "kern.proc")) {
            memset(oldp, 0, *oldlenp);
            return 0;
        }
    }
    return orig_sysctlbyname ? orig_sysctlbyname(name, oldp, oldlenp, newp, newlen) : 0;
}

static void* my_dlopen(const char *path, int mode) {
    return orig_dlopen ? orig_dlopen(path, mode) : NULL;
}

static void* my_dlsym(void *handle, const char *symbol) {
    if (symbol) {
        if (strstr(symbol, "ptrace") || strstr(symbol, "sysctl") ||
            strstr(symbol, "task_for_pid") || strstr(symbol, "vm_read")) {
            return NULL;
        }
    }
    return orig_dlsym ? orig_dlsym(handle, symbol) : NULL;
}

static int my_task_for_pid(mach_port_t target_tport, int pid, mach_port_t *tn) {
    return KERN_FAILURE;
}

static int my_vm_read_overwrite(vm_map_t target_task, vm_address_t address, vm_size_t size, vm_address_t data, vm_size_t *outsize) {
    return KERN_FAILURE;
}

static int my_vm_write(vm_map_t target_task, vm_address_t address, vm_offset_t data, mach_msg_type_number_t dataCnt) {
    return KERN_FAILURE;
}

static int my_vm_protect(vm_map_t target_task, vm_address_t address, vm_size_t size, boolean_t set_max, vm_prot_t new_protection) {
    return orig_vm_protect ? orig_vm_protect(target_task, address, size, set_max, new_protection) : KERN_SUCCESS;
}

static int my_mach_vm_protect(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, boolean_t set_max, vm_prot_t new_protection) {
    return orig_mach_vm_protect ? orig_mach_vm_protect(target_task, address, size, set_max, new_protection) : KERN_SUCCESS;
}

// Keychain
static OSStatus my_SecItemCopyMatching(CFDictionaryRef query, CFTypeRef *result) {
    return errSecItemNotFound;
}
static OSStatus my_SecItemAdd(CFDictionaryRef attributes, CFTypeRef *result) {
    return errSecDuplicateItem;
}
static OSStatus my_SecItemUpdate(CFDictionaryRef query, CFDictionaryRef attributesToUpdate) {
    return errSecItemNotFound;
}
static OSStatus my_SecItemDelete(CFDictionaryRef query) {
    return errSecSuccess;
}

// SecKey
static SecKeyRef my_SecKeyCreateRandomKey(CFDictionaryRef parameters, CFErrorRef *error) { return NULL; }
static SecKeyRef my_SecKeyCopyPublicKey(SecKeyRef key) { return NULL; }
static CFDataRef my_SecKeyCreateSignature(SecKeyRef key, SecKeyAlgorithm algorithm, CFDataRef dataToSign, CFErrorRef *error) {
    return CFDataCreate(NULL, (const UInt8*)"fake_signature", 14);
}
static Boolean my_SecKeyVerifySignature(SecKeyRef key, SecKeyAlgorithm algorithm, CFDataRef dataToSign, CFDataRef signature, CFErrorRef *error) {
    return true;
}

// CommonCrypto
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

// OpenSSL
static int my_RSA_verify(int type, const unsigned char *m, unsigned int m_len, const unsigned char *sig, unsigned int sig_len, RSA *rsa) { return 1; }
static int my_RSA_sign(int type, const unsigned char *m, unsigned int m_len, unsigned char *sig, unsigned int *sig_len, RSA *rsa) {
    if (sig_len) *sig_len = 0;
    return 0;
}
static int my_EVP_PKEY_verify(EVP_PKEY_CTX *ctx, const unsigned char *sig, size_t sig_len, const unsigned char *tbs, size_t tbs_len) { return 1; }
static int my_X509_verify_cert(X509_STORE_CTX *ctx) { return 1; }
static int my_X509_check_private_key(X509 *x509, EVP_PKEY *pkey) { return 1; }
static EVP_PKEY* my_PEM_read_bio_PrivateKey(BIO *bp, EVP_PKEY **x, pem_password_cb *cb, void *u) { return NULL; }
static int my_SSL_CTX_use_PrivateKey_file(SSL_CTX *ctx, const char *file, int type) { return 1; }
static int my_SSL_CTX_check_private_key(SSL_CTX *ctx) { return 1; }
static int my_SSL_CTX_load_verify_locations(SSL_CTX *ctx, const char *CAfile, const char *CApath) { return 1; }

// Environment check replacements
static bool my_is_jb(void) { return false; }
static bool my_ROOTED(void) { return false; }
static bool my_DEBUGGER_ATTACHED(void) { return false; }
static bool my_isDebuggerAttached(void) { return false; }
static bool my_checkJailbreak(void) { return false; }
static bool my_hasCydia(void) { return false; }
static bool my_isJailbroken_c(void) { return false; }
static bool my_amIBeingDebugged(void) { return false; }

// ============================================================================
// NEW: Replacement functions for Security / Trust
// ============================================================================

// SecTrustEvaluate – force success
static OSStatus my_SecTrustEvaluate(SecTrustRef trust, SecTrustResultType *result) {
    if (result) *result = kSecTrustResultProceed;
    return errSecSuccess;
}

// SecTrustCopyPublicKey – call original (safe)
static SecKeyRef my_SecTrustCopyPublicKey(SecTrustRef trust) {
    if (orig_SecTrustCopyPublicKey)
        return orig_SecTrustCopyPublicKey(trust);
    return NULL;
}

// SecTrustGetCertificateAtIndex – call original
static SecCertificateRef my_SecTrustGetCertificateAtIndex(SecTrustRef trust, CFIndex ix) {
    if (orig_SecTrustGetCertificateAtIndex)
        return orig_SecTrustGetCertificateAtIndex(trust, ix);
    return NULL;
}

// SecTrustGetCertificateCount – call original
static CFIndex my_SecTrustGetCertificateCount(SecTrustRef trust) {
    if (orig_SecTrustGetCertificateCount)
        return orig_SecTrustGetCertificateCount(trust);
    return 0;
}

// SecTrustGetTrustResult – return proceed
static OSStatus my_SecTrustGetTrustResult(SecTrustRef trust, SecTrustResultType *result) {
    if (result) *result = kSecTrustResultProceed;
    return errSecSuccess;
}

// SecTrustSetAnchorCertificates – call original
static OSStatus my_SecTrustSetAnchorCertificates(SecTrustRef trust, CFArrayRef anchorCertificates) {
    if (orig_SecTrustSetAnchorCertificates)
        return orig_SecTrustSetAnchorCertificates(trust, anchorCertificates);
    return errSecSuccess;
}

// SecTrustSetAnchorCertificatesOnly – call original
static OSStatus my_SecTrustSetAnchorCertificatesOnly(SecTrustRef trust, Boolean anchorCertificatesOnly) {
    if (orig_SecTrustSetAnchorCertificatesOnly)
        return orig_SecTrustSetAnchorCertificatesOnly(trust, anchorCertificatesOnly);
    return errSecSuccess;
}

// SecTrustSetPolicies – call original
static OSStatus my_SecTrustSetPolicies(SecTrustRef trust, CFTypeRef policies) {
    if (orig_SecTrustSetPolicies)
        return orig_SecTrustSetPolicies(trust, policies);
    return errSecSuccess;
}

// SecTrustSetVerifyDate – call original
static OSStatus my_SecTrustSetVerifyDate(SecTrustRef trust, CFDateRef verifyDate) {
    if (orig_SecTrustSetVerifyDate)
        return orig_SecTrustSetVerifyDate(trust, verifyDate);
    return errSecSuccess;
}

// SecCertificateCopyData – call original
static CFDataRef my_SecCertificateCopyData(SecCertificateRef certificate) {
    if (orig_SecCertificateCopyData)
        return orig_SecCertificateCopyData(certificate);
    return NULL;
}

// SecCertificateCopyKey – call original
static SecKeyRef my_SecCertificateCopyKey(SecCertificateRef certificate) {
    if (orig_SecCertificateCopyKey)
        return orig_SecCertificateCopyKey(certificate);
    return NULL;
}

// SecCertificateCreateWithData – call original
static SecCertificateRef my_SecCertificateCreateWithData(CFAllocatorRef allocator, CFDataRef data) {
    if (orig_SecCertificateCreateWithData)
        return orig_SecCertificateCreateWithData(allocator, data);
    return NULL;
}

// SecPolicyCreateSSL – call original
static SecPolicyRef my_SecPolicyCreateSSL(Boolean server, CFStringRef hostname) {
    if (orig_SecPolicyCreateSSL)
        return orig_SecPolicyCreateSSL(server, hostname);
    return NULL;
}

// SecPolicyCreateBasicX509 – call original
static SecPolicyRef my_SecPolicyCreateBasicX509(void) {
    if (orig_SecPolicyCreateBasicX509)
        return orig_SecPolicyCreateBasicX509();
    return NULL;
}

// SSLCreateContext – call original
static SSLContextRef my_SSLCreateContext(CFAllocatorRef allocator, SSLProtocolSide protocolSide, SSLConnectionType connectionType) {
    if (orig_SSLCreateContext)
        return orig_SSLCreateContext(allocator, protocolSide, connectionType);
    return NULL;
}

// SSLHandshake – call original
static OSStatus my_SSLHandshake(SSLContextRef context) {
    if (orig_SSLHandshake)
        return orig_SSLHandshake(context);
    return errSecSuccess;
}

// SSLSetSessionOption – call original
static OSStatus my_SSLSetSessionOption(SSLContextRef context, SSLSessionOption option, Boolean value) {
    if (orig_SSLSetSessionOption)
        return orig_SSLSetSessionOption(context, option, value);
    return errSecSuccess;
}

// SSLSetPeerDomainName – call original
static OSStatus my_SSLSetPeerDomainName(SSLContextRef context, const char *peerName, size_t peerNameLen) {
    if (orig_SSLSetPeerDomainName)
        return orig_SSLSetPeerDomainName(context, peerName, peerNameLen);
    return errSecSuccess;
}

// SSLSetCertificate – call original
static OSStatus my_SSLSetCertificate(SSLContextRef context, CFArrayRef certs) {
    if (orig_SSLSetCertificate)
        return orig_SSLSetCertificate(context, certs);
    return errSecSuccess;
}

// CFNetworkCopySystemProxySettings – call original
static CFDictionaryRef my_CFNetworkCopySystemProxySettings(void) {
    if (orig_CFNetworkCopySystemProxySettings)
        return orig_CFNetworkCopySystemProxySettings();
    return NULL;
}

// CFNetworkCopyProxiesForURL – call original
static CFArrayRef my_CFNetworkCopyProxiesForURL(CFURLRef url, CFDictionaryRef proxySettings) {
    if (orig_CFNetworkCopyProxiesForURL)
        return orig_CFNetworkCopyProxiesForURL(url, proxySettings);
    return NULL;
}

// SCNetworkReachabilityGetFlags – call original
static Boolean my_SCNetworkReachabilityGetFlags(SCNetworkReachabilityRef target, SCNetworkReachabilityFlags *flags) {
    if (orig_SCNetworkReachabilityGetFlags)
        return orig_SCNetworkReachabilityGetFlags(target, flags);
    if (flags) *flags = 0;
    return FALSE;
}

// SCNetworkReachabilityCreateWithName – call original
static SCNetworkReachabilityRef my_SCNetworkReachabilityCreateWithName(CFAllocatorRef allocator, const char *name) {
    if (orig_SCNetworkReachabilityCreateWithName)
        return orig_SCNetworkReachabilityCreateWithName(allocator, name);
    return NULL;
}

// SCNetworkReachabilityCreateWithAddress – call original
static SCNetworkReachabilityRef my_SCNetworkReachabilityCreateWithAddress(CFAllocatorRef allocator, const struct sockaddr *address) {
    if (orig_SCNetworkReachabilityCreateWithAddress)
        return orig_SCNetworkReachabilityCreateWithAddress(allocator, address);
    return NULL;
}

// The following are constants, not functions – we leave them unhooked.
// kCFStreamSSLValidatesCertificateChain, kCFStreamSSLAllowsAnyRoot, etc. are CFString constants.
// CFStreamPropertySSLSettings is a constant. Hooking them is neither possible nor necessary.

// ============================================================================
// Objective-C swizzling
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
    Class deviceCls = objc_getClass("UIDevice");
    if (deviceCls) {
        SEL sel = @selector(identifierForVendor);
        Method m = class_getInstanceMethod(deviceCls, sel);
        if (m) {
            orig_UIDevice_identifierForVendor = method_getImplementation(m);
            method_setImplementation(m, (IMP)my_UIDevice_identifierForVendor);
        }
    }
    Class laContextCls = objc_getClass("LAContext");
    if (laContextCls) {
        SEL sel1 = @selector(evaluatePolicy:localizedReason:reply:);
        Method m1 = class_getInstanceMethod(laContextCls, sel1);
        if (m1) {
            method_setImplementation(m1, (IMP)my_LAContext_evaluatePolicy);
        }
        SEL sel2 = @selector(canEvaluatePolicy:error:);
        Method m2 = class_getInstanceMethod(laContextCls, sel2);
        if (m2) {
            method_setImplementation(m2, (IMP)my_LAContext_canEvaluatePolicy);
        }
    }
}

// ============================================================================
// fishhook
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
        // New bindings
        {"SecTrustEvaluate", (void *)my_SecTrustEvaluate, (void **)&orig_SecTrustEvaluate},
        {"SecTrustCopyPublicKey", (void *)my_SecTrustCopyPublicKey, (void **)&orig_SecTrustCopyPublicKey},
        {"SecTrustGetCertificateAtIndex", (void *)my_SecTrustGetCertificateAtIndex, (void **)&orig_SecTrustGetCertificateAtIndex},
        {"SecTrustGetCertificateCount", (void *)my_SecTrustGetCertificateCount, (void **)&orig_SecTrustGetCertificateCount},
        {"SecTrustGetTrustResult", (void *)my_SecTrustGetTrustResult, (void **)&orig_SecTrustGetTrustResult},
        {"SecTrustSetAnchorCertificates", (void *)my_SecTrustSetAnchorCertificates, (void **)&orig_SecTrustSetAnchorCertificates},
        {"SecTrustSetAnchorCertificatesOnly", (void *)my_SecTrustSetAnchorCertificatesOnly, (void **)&orig_SecTrustSetAnchorCertificatesOnly},
        {"SecTrustSetPolicies", (void *)my_SecTrustSetPolicies, (void **)&orig_SecTrustSetPolicies},
        {"SecTrustSetVerifyDate", (void *)my_SecTrustSetVerifyDate, (void **)&orig_SecTrustSetVerifyDate},
        {"SecCertificateCopyData", (void *)my_SecCertificateCopyData, (void **)&orig_SecCertificateCopyData},
        {"SecCertificateCopyKey", (void *)my_SecCertificateCopyKey, (void **)&orig_SecCertificateCopyKey},
        {"SecCertificateCreateWithData", (void *)my_SecCertificateCreateWithData, (void **)&orig_SecCertificateCreateWithData},
        {"SecPolicyCreateSSL", (void *)my_SecPolicyCreateSSL, (void **)&orig_SecPolicyCreateSSL},
        {"SecPolicyCreateBasicX509", (void *)my_SecPolicyCreateBasicX509, (void **)&orig_SecPolicyCreateBasicX509},
        {"SSLCreateContext", (void *)my_SSLCreateContext, (void **)&orig_SSLCreateContext},
        {"SSLHandshake", (void *)my_SSLHandshake, (void **)&orig_SSLHandshake},
        {"SSLSetSessionOption", (void *)my_SSLSetSessionOption, (void **)&orig_SSLSetSessionOption},
        {"SSLSetPeerDomainName", (void *)my_SSLSetPeerDomainName, (void **)&orig_SSLSetPeerDomainName},
        {"SSLSetCertificate", (void *)my_SSLSetCertificate, (void **)&orig_SSLSetCertificate},
        {"CFNetworkCopySystemProxySettings", (void *)my_CFNetworkCopySystemProxySettings, (void **)&orig_CFNetworkCopySystemProxySettings},
        {"CFNetworkCopyProxiesForURL", (void *)my_CFNetworkCopyProxiesForURL, (void **)&orig_CFNetworkCopyProxiesForURL},
        {"SCNetworkReachabilityGetFlags", (void *)my_SCNetworkReachabilityGetFlags, (void **)&orig_SCNetworkReachabilityGetFlags},
        {"SCNetworkReachabilityCreateWithName", (void *)my_SCNetworkReachabilityCreateWithName, (void **)&orig_SCNetworkReachabilityCreateWithName},
        {"SCNetworkReachabilityCreateWithAddress", (void *)my_SCNetworkReachabilityCreateWithAddress, (void **)&orig_SCNetworkReachabilityCreateWithAddress},
    };
    rebind_symbols(bindings, sizeof(bindings)/sizeof(bindings[0]));
}

// ============================================================================
// __interpose
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
    if (strstr(format, "debug") || strstr(format, "jailbreak")) {
        return 0;
    }
    va_list args;
    va_start(args, format);
    int ret = vprintf(format, args);
    va_end(args);
    return ret;
}

// ============================================================================
// Environment checks
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

int is_jailbroken_paths() {
    const char *paths[] = {
        "/Applications/Cydia.app",
        "/Library/MobileSubstrate/MobileSubstrate.dylib",
        "/bin/bash",
        "/usr/sbin/sshd",
        "/etc/apt",
        "/private/var/lib/apt/",
        "/private/var/stash",
        "/usr/libexec/cydia",
        "/usr/sbin/frida-server",
        "/usr/bin/ssh",
        "/var/checkra1n.dmg",
        "/.bootstrapped",
        NULL
    };
    for (int i = 0; paths[i] != NULL; i++) {
        if (access(paths[i], F_OK) == 0) return 1;
    }
    return 0;
}

int is_cydia_installed() {
#if TARGET_OS_IPHONE
    Class lsApplicationWorkspace = objc_getClass("LSApplicationWorkspace");
    if (lsApplicationWorkspace) {
        SEL defaultWorkspace = sel_registerName("defaultWorkspace");
        SEL openApplicationWithBundleID = sel_registerName("openApplicationWithBundleID:");
        id workspace = ((id (*)(id, SEL))objc_msgSend)((id)lsApplicationWorkspace, defaultWorkspace);
        if (workspace) {
            int opened = ((int (*)(id, SEL, id))objc_msgSend)(workspace, openApplicationWithBundleID, @"com.saurik.Cydia");
            return opened;
        }
    }
#endif
    return 0;
}

int is_dyld_hijacked() {
    if (getenv("DYLD_INSERT_LIBRARIES") != NULL) return 1;
    if (getenv("DYLD_FORCE_FLAT_NAMESPACE") != NULL) return 1;
    return 0;
}

int is_debugger_attached() {
    int name[4];
    struct kinfo_proc info;
    size_t info_size = sizeof(info);
    info.kp_proc.p_flag = 0;
    name[0] = CTL_KERN;
    name[1] = KERN_PROC;
    name[2] = KERN_PROC_PID;
    name[3] = getpid();
    if (sysctl(name, 4, &
