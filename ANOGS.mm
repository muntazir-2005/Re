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
#import <SystemConfiguration/SystemConfiguration.h>
#import <dispatch/dispatch.h> // تم إضافة هذا الملف للتعامل مع التوقيت الآمن GCD

#if TARGET_OS_IPHONE
#import <objc/runtime.h>
#import <objc/message.h>
#import <LocalAuthentication/LocalAuthentication.h>
#endif

#include "fishhook.h"

// ptrace
#define PT_DENY_ATTACH 31
typedef int (*ptrace_ptr_t)(int, pid_t, caddr_t, int);
static ptrace_ptr_t real_ptrace = NULL;
static void load_real_ptrace(void) {
    if (!real_ptrace) real_ptrace = (ptrace_ptr_t)dlsym(RTLD_DEFAULT, "ptrace");
}

// OpenSSL types (declarations only)
typedef struct rsa_st RSA;
typedef struct evp_pkey_st EVP_PKEY;
typedef struct evp_pkey_ctx_st EVP_PKEY_CTX;
typedef struct x509_st X509;
typedef struct X509_store_ctx_st X509_STORE_CTX;
typedef struct ssl_ctx_st SSL_CTX;
typedef struct bio_st BIO;
typedef int pem_password_cb(char *buf, int size, int rwflag, void *userdata);

// ========== Original function pointers ==========
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

// ========== Security / Trust functions ==========
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

// ========== Replacement functions ==========
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

static int my_task_for_pid(mach_port_t target_tport, int pid, mach_port_t *tn) { return KERN_FAILURE; }
static int my_vm_read_overwrite(vm_map_t target_task, vm_address_t address, vm_size_t size, vm_address_t data, vm_size_t *outsize) { return KERN_FAILURE; }
static int my_vm_write(vm_map_t target_task, vm_address_t address, vm_offset_t data, mach_msg_type_number_t dataCnt) { return KERN_FAILURE; }
static int my_vm_protect(vm_map_t target_task, vm_address_t address, vm_size_t size, boolean_t set_max, vm_prot_t new_protection) {
    return orig_vm_protect ? orig_vm_protect(target_task, address, size, set_max, new_protection) : KERN_SUCCESS;
}
static int my_mach_vm_protect(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, boolean_t set_max, vm_prot_t new_protection) {
    return orig_mach_vm_protect ? orig_mach_vm_protect(target_task, address, size, set_max, new_protection) : KERN_SUCCESS;
}

static OSStatus my_SecItemCopyMatching(CFDictionaryRef query, CFTypeRef *result) { return errSecItemNotFound; }
static OSStatus my_SecItemAdd(CFDictionaryRef attributes, CFTypeRef *result) { return errSecDuplicateItem; }
static OSStatus my_SecItemUpdate(CFDictionaryRef query, CFDictionaryRef attributesToUpdate) { return errSecItemNotFound; }
static OSStatus my_SecItemDelete(CFDictionaryRef query) { return errSecSuccess; }

static SecKeyRef my_SecKeyCreateRandomKey(CFDictionaryRef parameters, CFErrorRef *error) { return NULL; }
static SecKeyRef my_SecKeyCopyPublicKey(SecKeyRef key) { return NULL; }
static CFDataRef my_SecKeyCreateSignature(SecKeyRef key, SecKeyAlgorithm algorithm, CFDataRef dataToSign, CFErrorRef *error) {
    return CFDataCreate(NULL, (const UInt8*)"fake_signature", 14);
}
static Boolean my_SecKeyVerifySignature(SecKeyRef key, SecKeyAlgorithm algorithm, CFDataRef dataToSign, CFDataRef signature, CFErrorRef *error) { return true; }

static CCCryptorStatus my_CCCrypt(CCOperation op, CCAlgorithm alg, CCOptions options, const void *key, size_t keyLength, const void *iv, const void *dataIn, size_t dataInLength, void *dataOut, size_t dataOutAvailable, size_t *dataOutMoved) {
    if (!dataOut || !dataOutMoved) return kCCParamError;
    size_t bytes = (dataInLength < dataOutAvailable) ? dataInLength : dataOutAvailable;
    memcpy(dataOut, dataIn, bytes);
    *dataOutMoved = bytes;
    return (bytes == dataInLength) ? kCCSuccess : kCCBufferTooSmall;
}

static int my_RSA_verify(int type, const unsigned char *m, unsigned int m_len, const unsigned char *sig, unsigned int sig_len, RSA *rsa) { return 1; }
static int my_RSA_sign(int type, const unsigned char *m, unsigned int m_len, unsigned char *sig, unsigned int *sig_len, RSA *rsa) { if (sig_len) *sig_len = 0; return 0; }
static int my_EVP_PKEY_verify(EVP_PKEY_CTX *ctx, const unsigned char *sig, size_t sig_len, const unsigned char *tbs, size_t tbs_len) { return 1; }
static int my_X509_verify_cert(X509_STORE_CTX *ctx) { return 1; }
static int my_X509_check_private_key(X509 *x509, EVP_PKEY *pkey) { return 1; }
static EVP_PKEY* my_PEM_read_bio_PrivateKey(BIO *bp, EVP_PKEY **x, pem_password_cb *cb, void *u) { return NULL; }
static int my_SSL_CTX_use_PrivateKey_file(SSL_CTX *ctx, const char *file, int type) { return 1; }
static int my_SSL_CTX_check_private_key(SSL_CTX *ctx) { return 1; }
static int my_SSL_CTX_load_verify_locations(SSL_CTX *ctx, const char *CAfile, const char *CApath) { return 1; }

// ========== Security replacements ==========
static OSStatus my_SecTrustEvaluate(SecTrustRef trust, SecTrustResultType *result) {
    if (result) *result = kSecTrustResultProceed;
    return errSecSuccess;
}
static SecKeyRef my_SecTrustCopyPublicKey(SecTrustRef trust) { return orig_SecTrustCopyPublicKey ? orig_SecTrustCopyPublicKey(trust) : NULL; }
static SecCertificateRef my_SecTrustGetCertificateAtIndex(SecTrustRef trust, CFIndex ix) { return orig_SecTrustGetCertificateAtIndex ? orig_SecTrustGetCertificateAtIndex(trust, ix) : NULL; }
static CFIndex my_SecTrustGetCertificateCount(SecTrustRef trust) { return orig_SecTrustGetCertificateCount ? orig_SecTrustGetCertificateCount(trust) : 0; }
static OSStatus my_SecTrustGetTrustResult(SecTrustRef trust, SecTrustResultType *result) { if (result) *result = kSecTrustResultProceed; return errSecSuccess; }
static OSStatus my_SecTrustSetAnchorCertificates(SecTrustRef trust, CFArrayRef anchorCertificates) { return orig_SecTrustSetAnchorCertificates ? orig_SecTrustSetAnchorCertificates(trust, anchorCertificates) : errSecSuccess; }
static OSStatus my_SecTrustSetAnchorCertificatesOnly(SecTrustRef trust, Boolean anchorCertificatesOnly) { return orig_SecTrustSetAnchorCertificatesOnly ? orig_SecTrustSetAnchorCertificatesOnly(trust, anchorCertificatesOnly) : errSecSuccess; }
static OSStatus my_SecTrustSetPolicies(SecTrustRef trust, CFTypeRef policies) { return orig_SecTrustSetPolicies ? orig_SecTrustSetPolicies(trust, policies) : errSecSuccess; }
static OSStatus my_SecTrustSetVerifyDate(SecTrustRef trust, CFDateRef verifyDate) { return orig_SecTrustSetVerifyDate ? orig_SecTrustSetVerifyDate(trust, verifyDate) : errSecSuccess; }
static CFDataRef my_SecCertificateCopyData(SecCertificateRef certificate) { return orig_SecCertificateCopyData ? orig_SecCertificateCopyData(certificate) : NULL; }
static SecKeyRef my_SecCertificateCopyKey(SecCertificateRef certificate) { return orig_SecCertificateCopyKey ? orig_SecCertificateCopyKey(certificate) : NULL; }
static SecCertificateRef my_SecCertificateCreateWithData(CFAllocatorRef allocator, CFDataRef data) { return orig_SecCertificateCreateWithData ? orig_SecCertificateCreateWithData(allocator, data) : NULL; }
static SecPolicyRef my_SecPolicyCreateSSL(Boolean server, CFStringRef hostname) { return orig_SecPolicyCreateSSL ? orig_SecPolicyCreateSSL(server, hostname) : NULL; }
static SecPolicyRef my_SecPolicyCreateBasicX509(void) { return orig_SecPolicyCreateBasicX509 ? orig_SecPolicyCreateBasicX509() : NULL; }
static SSLContextRef my_SSLCreateContext(CFAllocatorRef allocator, SSLProtocolSide protocolSide, SSLConnectionType connectionType) { return orig_SSLCreateContext ? orig_SSLCreateContext(allocator, protocolSide, connectionType) : NULL; }
static OSStatus my_SSLHandshake(SSLContextRef context) { return orig_SSLHandshake ? orig_SSLHandshake(context) : errSecSuccess; }
static OSStatus my_SSLSetSessionOption(SSLContextRef context, SSLSessionOption option, Boolean value) { return orig_SSLSetSessionOption ? orig_SSLSetSessionOption(context, option, value) : errSecSuccess; }
static OSStatus my_SSLSetPeerDomainName(SSLContextRef context, const char *peerName, size_t peerNameLen) { return orig_SSLSetPeerDomainName ? orig_SSLSetPeerDomainName(context, peerName, peerNameLen) : errSecSuccess; }
static OSStatus my_SSLSetCertificate(SSLContextRef context, CFArrayRef certs) { return orig_SSLSetCertificate ? orig_SSLSetCertificate(context, certs) : errSecSuccess; }
static CFDictionaryRef my_CFNetworkCopySystemProxySettings(void) { return orig_CFNetworkCopySystemProxySettings ? orig_CFNetworkCopySystemProxySettings() : NULL; }
static CFArrayRef my_CFNetworkCopyProxiesForURL(CFURLRef url, CFDictionaryRef proxySettings) { return orig_CFNetworkCopyProxiesForURL ? orig_CFNetworkCopyProxiesForURL(url, proxySettings) : NULL; }
static Boolean my_SCNetworkReachabilityGetFlags(SCNetworkReachabilityRef target, SCNetworkReachabilityFlags *flags) {
    return orig_SCNetworkReachabilityGetFlags ? orig_SCNetworkReachabilityGetFlags(target, flags) : FALSE;
}
static SCNetworkReachabilityRef my_SCNetworkReachabilityCreateWithName(CFAllocatorRef allocator, const char *name) {
    return orig_SCNetworkReachabilityCreateWithName ? orig_SCNetworkReachabilityCreateWithName(allocator, name) : NULL;
}
static SCNetworkReachabilityRef my_SCNetworkReachabilityCreateWithAddress(CFAllocatorRef allocator, const struct sockaddr *address) {
    return orig_SCNetworkReachabilityCreateWithAddress ? orig_SCNetworkReachabilityCreateWithAddress(allocator, address) : NULL;
}

// ========== Objective-C swizzling ==========
static IMP orig_UIDevice_identifierForVendor;
static id my_UIDevice_identifierForVendor(id self, SEL _cmd) {
    return [[NSUUID alloc] initWithUUIDString:@"00000000-0000-0000-0000-000000000000"];
}
static void my_LAContext_evaluatePolicy(id self, SEL _cmd, LAPolicy policy, NSString *localizedReason, void(^reply)(BOOL success, NSError *error)) {
    if (reply) reply(YES, nil);
}
static BOOL my_LAContext_canEvaluatePolicy(id self, SEL _cmd, LAPolicy policy, NSError **error) { return YES; }

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
        if (m1) method_setImplementation(m1, (IMP)my_LAContext_evaluatePolicy);
        SEL sel2 = @selector(canEvaluatePolicy:error:);
        Method m2 = class_getInstanceMethod(laContextCls, sel2);
        if (m2) method_setImplementation(m2, (IMP)my_LAContext_canEvaluatePolicy);
    }
}

// ========== fishhook rebinding ==========
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

// ========== __interpose for printf ==========
typedef struct interpose_s { void *new_func; void *orig_func; } interpose_t;
#define INTERPOSE(new, orig) __attribute__((used)) static const interpose_t interpose_##new __attribute__((section("__DATA,__interpose"))) = { (void *)new, (void *)orig };
static int my_printf(const char *format, ...) {
    if (strstr(format, "debug") || strstr(format, "jailbreak")) return 0;
    va_list args; va_start(args, format); int ret = vprintf(format, args); va_end(args); return ret;
}
INTERPOSE(my_printf, printf)

// ========== Constructor with immediate execution (no delay, no crash) ==========
__attribute__((constructor))
void init_hook() {
    printf("\n========================================\n");
    printf("      تم تشغيل الحماية بنجاح           \n");
    printf("========================================\n");
    
    srand((unsigned int)time(NULL));
    load_real_ptrace();
    fishhook_bindings();
    swizzle_objc_methods();

    // جزء إظهار الرسالة الترحيبية بعد 5 ثوانٍ بشكل آمن بالخلفية
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        
        // طباعة داخل الـ Console
        printf("\n[Welcome] أهلاً بك! تم تحميل الأداة بنجاح.\n");
        
        #if TARGET_OS_IPHONE
        // جلب كلاسات النظام ديناميكياً لضمان التوافق مع الكود الخاص بك
        Class alertCls = objc_getClass("UIAlertController");
        Class actionCls = objc_getClass("UIAlertAction");
        Class appCls = objc_getClass("UIApplication");
        
        if (alertCls && actionCls && appCls) {
            // إنشاء نافذة التنبيه (Alert)
            id alert = [alertCls alertControllerWithTitle:@"مرحباً بك"
                                                 message:@"تم تشغيل الأداة بنجاح!"
                                          preferredStyle:1]; // 1 تعني Alert
            
            // إضافة زر موافق للإغلاق
            id defaultAction = [actionCls actionWithTitle:@"موافق" style:0 handler:nil];
            ((void (*)(id, SEL, id))objc_msgSend)(alert, sel_registerName("addAction:"), defaultAction);
            
            // العثور على الواجهة الحالية للتطبيق لعرض التنبيه فوقها
            id sharedApp = ((id (*)(id, SEL))objc_msgSend)(appCls, sel_registerName("sharedApplication"));
            if (sharedApp) {
                id keyWindow = ((id (*)(id, SEL))objc_msgSend)(sharedApp, sel_registerName("keyWindow"));
                if (keyWindow) {
                    id rootViewController = ((id (*)(id, SEL))objc_msgSend)(keyWindow, sel_registerName("rootViewController"));
                    if (rootViewController) {
                        // عرض الرسالة على الشاشة للمستخدم
                        ((void (*)(id, SEL, id, BOOL, id))objc_msgSend)(rootViewController, sel_registerName("presentViewController:animated:completion:"), alert, YES, nil);
                    }
                }
            }
        }
        #endif
    });
}
