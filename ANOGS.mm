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
#import <CommonCrypto/CommonHMAC.h>
#import <Security/Security.h>
#import <Security/SecKey.h>
#import <Security/SecureTransport.h>   // هذا يعرف SSLContextRef و SSLCipherSuite و SSLSessionState
#import <time.h>
#import <dispatch/dispatch.h>
#import <UIKit/UIKit.h>

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
// Original function pointers
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

// SecKey (original)
static SecKeyRef (*orig_SecKeyCreateRandomKey)(CFDictionaryRef parameters, CFErrorRef *error);
static SecKeyRef (*orig_SecKeyCopyPublicKey)(SecKeyRef key);
static CFDataRef (*orig_SecKeyCreateSignature)(SecKeyRef key, SecKeyAlgorithm algorithm, CFDataRef dataToSign, CFErrorRef *error);
static Boolean (*orig_SecKeyVerifySignature)(SecKeyRef key, SecKeyAlgorithm algorithm, CFDataRef dataToSign, CFDataRef signature, CFErrorRef *error);

// Additional Security.framework functions
static OSStatus (*orig_SecTrustEvaluate)(SecTrustRef trust, SecTrustResultType *result);
static int (*orig_SecKeyRawVerify)(SecKeyRef key, SecPadding padding, const uint8_t *signedData, size_t signedDataLen, const uint8_t *signature, size_t signatureLen);
static int (*orig_SecKeyRawSign)(SecKeyRef key, SecPadding padding, const uint8_t *hashToSign, size_t hashToSignLen, uint8_t *signedData, size_t *signedDataLen);
static CFDataRef (*orig_SecKeyCreateEncryptedData)(SecKeyRef key, SecKeyAlgorithm algorithm, CFDataRef plaintext, CFErrorRef *error);
static CFDataRef (*orig_SecKeyDecrypt)(SecKeyRef key, SecPadding padding, const uint8_t *cipherText, size_t cipherTextLen, size_t *plainTextLen);
static CFDataRef (*orig_SecKeyEncrypt)(SecKeyRef key, SecPadding padding, const uint8_t *plainText, size_t plainTextLen, size_t *cipherTextLen);
static OSStatus (*orig_SecPKCS12Import)(CFDataRef pkcs12_data, CFDictionaryRef options, CFArrayRef *items);
static CFTypeRef (*orig_SecCertificateCopyKey)(SecCertificateRef certificate);
static CFDataRef (*orig_SecCertificateCopyData)(SecCertificateRef certificate);
static SecPolicyRef (*orig_SecPolicyCreateSSL)(Boolean server, CFStringRef hostname);
static CFTypeRef (*orig_SecTrustCopyPublicKey)(SecTrustRef trust);
static CFArrayRef (*orig_SecTrustCopyPolicies)(SecTrustRef trust);
static CFIndex (*orig_SecTrustGetCertificateCount)(SecTrustRef trust);
static SecCertificateRef (*orig_SecTrustGetCertificateAtIndex)(SecTrustRef trust, CFIndex ix);
static CFDataRef (*orig_SecKeyCopyExternalRepresentation)(SecKeyRef key, CFErrorRef *error);
static CFDictionaryRef (*orig_SecKeyCopyAttributes)(SecKeyRef key);
static size_t (*orig_SecKeyGetBlockSize)(SecKeyRef key);

// SSL / CFNetwork functions (types are now from SecureTransport.h)
static OSStatus (*orig_SSLHandshake)(SSLContextRef context);
static OSStatus (*orig_SSLRead)(SSLContextRef context, void *data, size_t dataLength, size_t *processed);
static OSStatus (*orig_SSLWrite)(SSLContextRef context, const void *data, size_t dataLength, size_t *processed);
static OSStatus (*orig_SSLSetCertificate)(SSLContextRef context, CFArrayRef certs);
static OSStatus (*orig_SSLCopyPeerTrust)(SSLContextRef context, SecTrustRef *trust);
static OSStatus (*orig_SSLGetNegotiatedCipher)(SSLContextRef context, SSLCipherSuite *cipherSuite);
static OSStatus (*orig_SSLSetPeerDomainName)(SSLContextRef context, const char *peerName, size_t peerNameLen);
static OSStatus (*orig_SSLSetSessionOption)(SSLContextRef context, SSLSessionOption option, Boolean value);
static OSStatus (*orig_SSLGetSessionState)(SSLContextRef context, SSLSessionState *state);
static OSStatus (*orig_SSLClose)(SSLContextRef context);
static Boolean (*orig_CFHostStartInfoResolution)(CFHostRef theHost, CFHostInfoType info, CFStreamError *error);
static CFArrayRef (*orig_CFHostGetAddressing)(CFHostRef theHost, Boolean *hasBeenResolved);
static CFArrayRef (*orig_CFNetworkCopySystemProxySettings)(void);
static CFDictionaryRef (*orig_CFNetworkCopyProxiesForURL)(CFURLRef url, CFDictionaryRef proxySettings);

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

// Objective-C runtime hooks
static id (*orig_objc_msgSend)(id self, SEL _cmd, ...);
static id (*orig_objc_retain)(id obj);
static void (*orig_objc_release)(id obj);
static id (*orig_objc_autorelease)(id obj);
static Class (*orig_objc_getClass)(const char *name);
static const char *(*orig_sel_getName)(SEL sel);
static IMP (*orig_method_getImplementation)(Method method);
static void (*orig_method_setImplementation)(Method method, IMP imp);
static void (*orig_method_exchangeImplementations)(Method m1, Method m2);
static BOOL (*orig_class_addMethod)(Class cls, SEL name, IMP imp, const char *types);
static IMP (*orig_class_replaceMethod)(Class cls, SEL name, IMP imp, const char *types);

// ============================================================================
// Replacement functions
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
static OSStatus my_SecItemCopyMatching(CFDictionaryRef query, CFTypeRef *result) { return errSecItemNotFound; }
static OSStatus my_SecItemAdd(CFDictionaryRef attributes, CFTypeRef *result) { return errSecDuplicateItem; }
static OSStatus my_SecItemUpdate(CFDictionaryRef query, CFDictionaryRef attributesToUpdate) { return errSecItemNotFound; }
static OSStatus my_SecItemDelete(CFDictionaryRef query) { return errSecSuccess; }

// SecKey
static SecKeyRef my_SecKeyCreateRandomKey(CFDictionaryRef parameters, CFErrorRef *error) { return NULL; }
static SecKeyRef my_SecKeyCopyPublicKey(SecKeyRef key) { return NULL; }
static CFDataRef my_SecKeyCreateSignature(SecKeyRef key, SecKeyAlgorithm algorithm, CFDataRef dataToSign, CFErrorRef *error) {
    return CFDataCreate(NULL, (const UInt8*)"fake_signature", 14);
}
static Boolean my_SecKeyVerifySignature(SecKeyRef key, SecKeyAlgorithm algorithm, CFDataRef dataToSign, CFDataRef signature, CFErrorRef *error) {
    return true;
}

// Additional Security
static OSStatus my_SecTrustEvaluate(SecTrustRef trust, SecTrustResultType *result) {
    if (result) *result = kSecTrustResultProceed;
    return errSecSuccess;
}
static int my_SecKeyRawVerify(SecKeyRef key, SecPadding padding, const uint8_t *signedData, size_t signedDataLen, const uint8_t *signature, size_t signatureLen) { return 0; }
static int my_SecKeyRawSign(SecKeyRef key, SecPadding padding, const uint8_t *hashToSign, size_t hashToSignLen, uint8_t *signedData, size_t *signedDataLen) {
    if (signedData && signedDataLen) {
        *signedDataLen = hashToSignLen;
        memcpy(signedData, hashToSign, hashToSignLen);
    }
    return 0;
}
static CFDataRef my_SecKeyCreateEncryptedData(SecKeyRef key, SecKeyAlgorithm algorithm, CFDataRef plaintext, CFErrorRef *error) {
    return CFDataCreate(kCFAllocatorDefault, CFDataGetBytePtr(plaintext), CFDataGetLength(plaintext));
}
static CFDataRef my_SecKeyDecrypt(SecKeyRef key, SecPadding padding, const uint8_t *cipherText, size_t cipherTextLen, size_t *plainTextLen) {
    if (plainTextLen) *plainTextLen = cipherTextLen;
    return CFDataCreate(kCFAllocatorDefault, cipherText, cipherTextLen);
}
static CFDataRef my_SecKeyEncrypt(SecKeyRef key, SecPadding padding, const uint8_t *plainText, size_t plainTextLen, size_t *cipherTextLen) {
    if (cipherTextLen) *cipherTextLen = plainTextLen;
    return CFDataCreate(kCFAllocatorDefault, plainText, plainTextLen);
}
static OSStatus my_SecPKCS12Import(CFDataRef pkcs12_data, CFDictionaryRef options, CFArrayRef *items) {
    if (items) *items = CFArrayCreate(kCFAllocatorDefault, NULL, 0, &kCFTypeArrayCallBacks);
    return errSecSuccess;
}
static CFTypeRef my_SecCertificateCopyKey(SecCertificateRef certificate) { return NULL; }
static CFDataRef my_SecCertificateCopyData(SecCertificateRef certificate) { return CFDataCreate(kCFAllocatorDefault, NULL, 0); }
static SecPolicyRef my_SecPolicyCreateSSL(Boolean server, CFStringRef hostname) { return NULL; }
static CFTypeRef my_SecTrustCopyPublicKey(SecTrustRef trust) { return NULL; }
static CFArrayRef my_SecTrustCopyPolicies(SecTrustRef trust) { return NULL; }
static CFIndex my_SecTrustGetCertificateCount(SecTrustRef trust) { return 0; }
static SecCertificateRef my_SecTrustGetCertificateAtIndex(SecTrustRef trust, CFIndex ix) { return NULL; }
static CFDataRef my_SecKeyCopyExternalRepresentation(SecKeyRef key, CFErrorRef *error) { return CFDataCreate(kCFAllocatorDefault, (const UInt8*)"fake_key_rep", 12); }
static CFDictionaryRef my_SecKeyCopyAttributes(SecKeyRef key) { return NULL; }
static size_t my_SecKeyGetBlockSize(SecKeyRef key) { return 256; }

// SSL / CFNetwork
static OSStatus my_SSLHandshake(SSLContextRef context) { return errSecSuccess; }
static OSStatus my_SSLRead(SSLContextRef context, void *data, size_t dataLength, size_t *processed) {
    if (processed) *processed = 0;
    return errSSLWouldBlock;
}
static OSStatus my_SSLWrite(SSLContextRef context, const void *data, size_t dataLength, size_t *processed) {
    if (processed) *processed = dataLength;
    return errSecSuccess;
}
static OSStatus my_SSLSetCertificate(SSLContextRef context, CFArrayRef certs) { return errSecSuccess; }
static OSStatus my_SSLCopyPeerTrust(SSLContextRef context, SecTrustRef *trust) {
    if (trust) *trust = NULL;
    return errSecSuccess;
}
static OSStatus my_SSLGetNegotiatedCipher(SSLContextRef context, SSLCipherSuite *cipherSuite) {
    if (cipherSuite) *cipherSuite = 0x1301;
    return errSecSuccess;
}
static OSStatus my_SSLSetPeerDomainName(SSLContextRef context, const char *peerName, size_t peerNameLen) { return errSecSuccess; }
static OSStatus my_SSLSetSessionOption(SSLContextRef context, SSLSessionOption option, Boolean value) { return errSecSuccess; }
static OSStatus my_SSLGetSessionState(SSLContextRef context, SSLSessionState *state) {
    if (state) *state = kSSLIdle;   // استخدم الثابت الصحيح بدلاً من 0
    return errSecSuccess;
}
static OSStatus my_SSLClose(SSLContextRef context) { return errSecSuccess; }
static Boolean my_CFHostStartInfoResolution(CFHostRef theHost, CFHostInfoType info, CFStreamError *error) { return true; }
static CFArrayRef my_CFHostGetAddressing(CFHostRef theHost, Boolean *hasBeenResolved) {
    if (hasBeenResolved) *hasBeenResolved = true;
    return CFArrayCreate(kCFAllocatorDefault, NULL, 0, &kCFTypeArrayCallBacks);
}
static CFArrayRef my_CFNetworkCopySystemProxySettings(void) { return NULL; }
static CFDictionaryRef my_CFNetworkCopyProxiesForURL(CFURLRef url, CFDictionaryRef proxySettings) { return NULL; }

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

// Environment checks
static bool my_is_jb(void) { return false; }
static bool my_ROOTED(void) { return false; }
static bool my_DEBUGGER_ATTACHED(void) { return false; }
static bool my_isDebuggerAttached(void) { return false; }
static bool my_checkJailbreak(void) { return false; }
static bool my_hasCydia(void) { return false; }
static bool my_isJailbroken_c(void) { return false; }
static bool my_amIBeingDebugged(void) { return false; }

// Objective-C passthrough
static id my_objc_msgSend(id self, SEL _cmd, ...) { return orig_objc_msgSend ? orig_objc_msgSend(self, _cmd) : nil; }
static id my_objc_retain(id obj) { return orig_objc_retain ? orig_objc_retain(obj) : obj; }
static void my_objc_release(id obj) { if (orig_objc_release) orig_objc_release(obj); }
static id my_objc_autorelease(id obj) { return orig_objc_autorelease ? orig_objc_autorelease(obj) : obj; }
static Class my_objc_getClass(const char *name) { return orig_objc_getClass ? orig_objc_getClass(name) : nil; }
static const char *my_sel_getName(SEL sel) { return orig_sel_getName ? orig_sel_getName(sel) : sel_getName(sel); }
static IMP my_method_getImplementation(Method method) { return orig_method_getImplementation ? orig_method_getImplementation(method) : NULL; }
static void my_method_setImplementation(Method method, IMP imp) { if (orig_method_setImplementation) orig_method_setImplementation(method, imp); }
static void my_method_exchangeImplementations(Method m1, Method m2) { if (orig_method_exchangeImplementations) orig_method_exchangeImplementations(m1, m2); }
static BOOL my_class_addMethod(Class cls, SEL name, IMP imp, const char *types) { return orig_class_addMethod ? orig_class_addMethod(cls, name, imp, types) : NO; }
static IMP my_class_replaceMethod(Class cls, SEL name, IMP imp, const char *types) { return orig_class_replaceMethod ? orig_class_replaceMethod(cls, name, imp, types) : NULL; }

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
// Fingerprint functions
// ============================================================================
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
        (id)kSecAttrService: @"com.anogs.bypass",
        (id)kSecValueData: [fp dataUsingEncoding:NSUTF8StringEncoding]
    };
    SecItemDelete((CFDictionaryRef)query);
    SecItemAdd((CFDictionaryRef)query, NULL);
}

static NSString* loadFingerprint() {
    NSDictionary *query = @{
        (id)kSecClass: (id)kSecClassGenericPassword,
        (id)kSecAttrService: @"com.anogs.bypass",
        (id)kSecReturnData: @YES,
        (id)kSecMatchLimit: (id)kSecMatchLimitOne
    };
    CFDataRef data = NULL;
    if (SecItemCopyMatching((CFDictionaryRef)query, (CFTypeRef *)&data) == errSecSuccess) {
        NSString *fp = [[NSString alloc] initWithData:(__bridge NSData *)data encoding:NSUTF8StringEncoding];
        CFRelease(data);
        return fp;
    }
    return nil;
}

// ============================================================================
// GUI for iOS 18
// ============================================================================
static void showFingerprintGUI(NSString *currentFP) {
    dispatch_async(dispatch_get_main_queue(), ^{
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"بصمة الجلسة"
                                                                       message:@"تم إنشاء بصمة فريدة لهذه الجلسة"
                                                                preferredStyle:UIAlertControllerStyleAlert];
        [alert addTextFieldWithConfigurationHandler:^(UITextField *textField) {
            textField.text = currentFP;
            textField.placeholder = @"البصمة";
            textField.enabled = NO;
            textField.font = [UIFont fontWithName:@"CourierNewPSMT" size:12];
            textField.textAlignment = NSTextAlignmentCenter;
        }];
        UIAlertAction *saveAction = [UIAlertAction actionWithTitle:@"حفظ البصمة" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
            saveFingerprint(currentFP);
            UIAlertController *confirm = [UIAlertController alertControllerWithTitle:@"تم الحفظ"
                                                                             message:@"تم حفظ البصمة في Keychain"
                                                                      preferredStyle:UIAlertControllerStyleAlert];
            [confirm addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
            UIWindow *keyWindow = nil;
            if (@available(iOS 13.0, *)) {
                for (UIWindowScene *scene in [UIApplication sharedApplication].connectedScenes) {
                    if (scene.activationState == UISceneActivationStateForegroundActive) {
                        keyWindow = scene.windows.firstObject;
                        break;
                    }
                }
            } else {
                keyWindow = [UIApplication sharedApplication].keyWindow;
            }
            [keyWindow.rootViewController presentViewController:confirm animated:YES completion:nil];
        }];
        UIAlertAction *loadAction = [UIAlertAction actionWithTitle:@"تحميل بصمة محفوظة" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
            NSString *saved = loadFingerprint();
            if (saved) {
                UIAlertController *showSaved = [UIAlertController alertControllerWithTitle:@"البصمة المحفوظة"
                                                                                   message:saved
                                                                            preferredStyle:UIAlertControllerStyleAlert];
                [showSaved addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
                UIWindow *keyWindow = nil;
                if (@available(iOS 13.0, *)) {
                    for (UIWindowScene *scene in [UIApplication sharedApplication].connectedScenes) {
                        if (scene.activationState == UISceneActivationStateForegroundActive) {
                            keyWindow = scene.windows.firstObject;
                            break;
                        }
                    }
                } else {
                    keyWindow = [UIApplication sharedApplication].keyWindow;
                }
                [keyWindow.rootViewController presentViewController:showSaved animated:YES completion:nil];
            } else {
                UIAlertController *noSaved = [UIAlertController alertControllerWithTitle:@"غير موجود"
                                                                                 message:@"لا توجد بصمة محفوظة مسبقاً"
                                                                          preferredStyle:UIAlertControllerStyleAlert];
                [noSaved addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
                UIWindow *keyWindow = nil;
                if (@available(iOS 13.0, *)) {
                    for (UIWindowScene *scene in [UIApplication sharedApplication].connectedScenes) {
                        if (scene.activationState == UISceneActivationStateForegroundActive) {
                            keyWindow = scene.windows.firstObject;
                            break;
                        }
                    }
                } else {
                    keyWindow = [UIApplication sharedApplication].keyWindow;
                }
                [keyWindow.rootViewController presentViewController:noSaved animated:YES completion:nil];
            }
        }];
        UIAlertAction *cancelAction = [UIAlertAction actionWithTitle:@"إلغاء" style:UIAlertActionStyleCancel handler:nil];
        [alert addAction:saveAction];
        [alert addAction:loadAction];
        [alert addAction:cancelAction];
        UIWindow *keyWindow = nil;
        if (@available(iOS 13.0, *)) {
            for (UIWindowScene *scene in [UIApplication sharedApplication].connectedScenes) {
                if (scene.activationState == UISceneActivationStateForegroundActive) {
                    keyWindow = scene.windows.firstObject;
                    break;
                }
            }
        } else {
            keyWindow = [UIApplication sharedApplication].keyWindow;
        }
        UIViewController *rootVC = keyWindow.rootViewController;
        if (rootVC) {
            [rootVC presentViewController:alert animated:YES completion:nil];
        } else {
            NSLog(@"No root view controller found to present fingerprint GUI");
        }
    });
}

// ============================================================================
// fishhook bindings (all symbols)
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
        {"SecTrustEvaluate", (void *)my_SecTrustEvaluate, (void **)&orig_SecTrustEvaluate},
        {"SecKeyRawVerify", (void *)my_SecKeyRawVerify, (void **)&orig_SecKeyRawVerify},
        {"SecKeyRawSign", (void *)my_SecKeyRawSign, (void **)&orig_SecKeyRawSign},
        {"SecKeyCreateEncryptedData", (void *)my_SecKeyCreateEncryptedData, (void **)&orig_SecKeyCreateEncryptedData},
        {"SecKeyDecrypt", (void *)my_SecKeyDecrypt, (void **)&orig_SecKeyDecrypt},
        {"SecKeyEncrypt", (void *)my_SecKeyEncrypt, (void **)&orig_SecKeyEncrypt},
        {"SecPKCS12Import", (void *)my_SecPKCS12Import, (void **)&orig_SecPKCS12Import},
        {"SecCertificateCopyKey", (void *)my_SecCertificateCopyKey, (void **)&orig_SecCertificateCopyKey},
        {"SecCertificateCopyData", (void *)my_SecCertificateCopyData, (void **)&orig_SecCertificateCopyData},
        {"SecPolicyCreateSSL", (void *)my_SecPolicyCreateSSL, (void **)&orig_SecPolicyCreateSSL},
        {"SecTrustCopyPublicKey", (void *)my_SecTrustCopyPublicKey, (void **)&orig_SecTrustCopyPublicKey},
        {"SecTrustCopyPolicies", (void *)my_SecTrustCopyPolicies, (void **)&orig_SecTrustCopyPolicies},
        {"SecTrustGetCertificateCount", (void *)my_SecTrustGetCertificateCount, (void **)&orig_SecTrustGetCertificateCount},
        {"SecTrustGetCertificateAtIndex", (void *)my_SecTrustGetCertificateAtIndex, (void **)&orig_SecTrustGetCertificateAtIndex},
        {"SecKeyCopyExternalRepresentation", (void *)my_SecKeyCopyExternalRepresentation, (void **)&orig_SecKeyCopyExternalRepresentation},
        {"SecKeyCopyAttributes", (void *)my_SecKeyCopyAttributes, (void **)&orig_SecKeyCopyAttributes},
        {"SecKeyGetBlockSize", (void *)my_SecKeyGetBlockSize, (void **)&orig_SecKeyGetBlockSize},
        {"SSLHandshake", (void *)my_SSLHandshake, (void **)&orig_SSLHandshake},
        {"SSLRead", (void *)my_SSLRead, (void **)&orig_SSLRead},
        {"SSLWrite", (void *)my_SSLWrite, (void **)&orig_SSLWrite},
        {"SSLSetCertificate", (void *)my_SSLSetCertificate, (void **)&orig_SSLSetCertificate},
        {"SSLCopyPeerTrust", (void *)my_SSLCopyPeerTrust, (void **)&orig_SSLCopyPeerTrust},
        {"SSLGetNegotiatedCipher", (void *)my_SSLGetNegotiatedCipher, (void **)&orig_SSLGetNegotiatedCipher},
        {"SSLSetPeerDomainName", (void *)my_SSLSetPeerDomainName, (void **)&orig_SSLSetPeerDomainName},
        {"SSLSetSessionOption", (void *)my_SSLSetSessionOption, (void **)&orig_SSLSetSessionOption},
        {"SSLGetSessionState", (void *)my_SSLGetSessionState, (void **)&orig_SSLGetSessionState},
        {"SSLClose", (void *)my_SSLClose, (void **)&orig_SSLClose},
        {"CFHostStartInfoResolution", (void *)my_CFHostStartInfoResolution, (void **)&orig_CFHostStartInfoResolution},
        {"CFHostGetAddressing", (void *)my_CFHostGetAddressing, (void **)&orig_CFHostGetAddressing},
        {"CFNetworkCopySystemProxySettings", (void *)my_CFNetworkCopySystemProxySettings, (void **)&orig_CFNetworkCopySystemProxySettings},
        {"CFNetworkCopyProxiesForURL", (void *)my_CFNetworkCopyProxiesForURL, (void **)&orig_CFNetworkCopyProxiesForURL},
        {"objc_msgSend", (void *)my_objc_msgSend, (void **)&orig_objc_msgSend},
        {"objc_retain", (void *)my_objc_retain, (void **)&orig_objc_retain},
        {"objc_release", (void *)my_objc_release, (void **)&orig_objc_release},
        {"objc_autorelease", (void *)my_objc_autorelease, (void **)&orig_objc_autorelease},
        {"objc_getClass", (void *)my_objc_getClass, (void **)&orig_objc_getClass},
        {"sel_getName", (void *)my_sel_getName, (void **)&orig_sel_getName},
        {"method_getImplementation", (void *)my_method_getImplementation, (void **)&orig_method_getImplementation},
        {"method_setImplementation", (void *)my_method_setImplementation, (void **)&orig_method_setImplementation},
        {"method_exchangeImplementations", (void *)my_method_exchangeImplementations, (void **)&orig_method_exchangeImplementations},
        {"class_addMethod", (void *)my_class_addMethod, (void **)&orig_class_addMethod},
        {"class_replaceMethod", (void *)my_class_replaceMethod, (void **)&orig_class_replaceMethod},
    };
    rebind_symbols(bindings, sizeof(bindings)/sizeof(bindings[0]));
}

// ============================================================================
// __interpose (for printf filtering)
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
// Environment checks (security detection)
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
    if (sysctl(name, 4, &info, &info_size, NULL, 0) == -1) return 0;
    return (info.kp_proc.p_flag & P_TRACED) != 0;
}

int ptrace_deny_attach() {
    load_real_ptrace();
    if (!real_ptrace) return 1;
    return (real_ptrace(PT_DENY_ATTACH, 0, 0, 0) == -1) ? 1 : 0;
}

int is_substrate_loaded() {
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char *name = _dyld_get_image_name(i);
        if (strstr(name, "MobileSubstrate") || strstr(name, "Substrate") || strstr(name, "CydiaSubstrate"))
            return 1;
    }
    return 0;
}

int is_ssh_running() { return (access("/usr/sbin/sshd", F_OK) == 0); }
int is_apt_installed() { return (access("/etc/apt", F_OK) == 0); }
int is_frida_installed() { return (access("/usr/sbin/frida-server", F_OK) == 0); }
int is_debugserver_installed() { return (access("/Developer/usr/bin/debugserver", F_OK) == 0); }

int check_provisioning() {
    FILE *fp = NULL;
    uint32_t size = 0;
    _NSGetExecutablePath(NULL, &size);
    char execPath[size];
    _NSGetExecutablePath(execPath, &size);
    char *lastSlash = strrchr(execPath, '/');
    if (lastSlash) {
        *lastSlash = '\0';
        char path[MAXPATHLEN];
        snprintf(path, sizeof(path), "%s/embedded.mobileprovision", execPath);
        fp = fopen(path, "r");
    }
    if (!fp) return 0;
    fseek(fp, 0, SEEK_END);
    long len = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    char *data = (char *)malloc(len + 1);
    fread(data, 1, len, fp);
    fclose(fp);
    data[len] = '\0';
    int is_debuggable = (strstr(data, "<key>get-task-allow</key><true/>") != NULL);
    free(data);
    return is_debuggable;
}

int check_env() {
    const char *vars[] = {"DYLD_PRINT_TO_FILE", "DYLD_INSERT_LIBRARIES", "CFNETWORK_DIAGNOSTICS", "OBJC_DISABLE_VALIDATION", NULL};
    for (int i = 0; vars[i] != NULL; i++) {
        if (getenv(vars[i]) != NULL) return 1;
    }
    return 0;
}

int check_ppid() {
    pid_t ppid = getppid();
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/exe", ppid);
    if (access(path, F_OK) == 0) {
        char target[256];
        ssize_t len = readlink(path, target, sizeof(target)-1);
        if (len != -1) {
            target[len] = '\0';
            if (strstr(target, "debugserver") || strstr(target, "lldb"))
                return 1;
        }
    }
    return 0;
}

int is_frida_loaded() {
    return (dlopen("frida-agent.dylib", RTLD_NOLOAD) != NULL);
}

void perform_security_checks() {
    int threat_level = 0;
    if (is_simulator()) threat_level += 10;
    if (is_jailbroken_paths()) threat_level += 20;
    if (is_cydia_installed()) threat_level += 10;
    if (is_dyld_hijacked()) threat_level += 30;
    if (is_debugger_attached()) threat_level += 50;
    if (ptrace_deny_attach()) threat_level += 30;
    if (is_substrate_loaded()) threat_level += 20;
    if (is_ssh_running()) threat_level += 10;
    if (is_apt_installed()) threat_level += 10;
    if (is_frida_installed() || is_frida_loaded()) threat_level += 40;
    if (is_debugserver_installed()) threat_level += 20;
    if (check_provisioning()) threat_level += 30;
    if (check_env()) threat_level += 10;
    if (check_ppid()) threat_level += 40;

    if (threat_level > 50) {
        usleep(rand() % 100000);
        _exit(1);
    }
}

// ============================================================================
// Delayed initialization with 20 seconds, banner, and fingerprint GUI
// ============================================================================
static void delayed_init(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        NSLog(@"✅ تم تشغيل الحمايه");
        UIWindow *keyWindow = nil;
        if (@available(iOS 13.0, *)) {
            for (UIWindowScene *scene in [UIApplication sharedApplication].connectedScenes) {
                if (scene.activationState == UISceneActivationStateForegroundActive) {
                    keyWindow = scene.windows.firstObject;
                    break;
                }
            }
        } else {
            keyWindow = [UIApplication sharedApplication].keyWindow;
        }
        UIViewController *rootVC = keyWindow.rootViewController;
        if (rootVC) {
            UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"الحماية" 
                                                                           message:@"تم تشغيل الحمايه" 
                                                                    preferredStyle:UIAlertControllerStyleAlert];
            [alert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
            [rootVC presentViewController:alert animated:YES completion:nil];
        } else {
            printf("\n\n********** تم تشغيل الحمايه **********\n\n");
        }
    });
    
    perform_security_checks();
    fishhook_bindings();
    swizzle_objc_methods();
    
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        NSString *fp = sessionFingerprint();
        showFingerprintGUI(fp);
    });
}

// ============================================================================
// Constructor – delayed by 20 seconds
// ============================================================================
__attribute__((constructor))
void init_hook(void) {
    srand((unsigned int)time(NULL));
    load_real_ptrace();
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(50.0 * NSEC_PER_SEC)), dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        delayed_init();
    });
}
