//  ViewController.m
//  واجهة تشغيل الحماية يدوياً

#import "ViewController.h"
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
#import <LocalAuthentication/LocalAuthentication.h>
#import <objc/runtime.h>
#import <objc/message.h>
#include "fishhook.h"

// ============================================================================
// تعريفات OpenSSL (بدون headers)
// ============================================================================
typedef struct rsa_st RSA;
typedef struct evp_pkey_st EVP_PKEY;
typedef struct evp_pkey_ctx_st EVP_PKEY_CTX;
typedef struct x509_st X509;
typedef struct X509_store_ctx_st X509_STORE_CTX;
typedef struct ssl_ctx_st SSL_CTX;
typedef struct bio_st BIO;
typedef int pem_password_cb(char *buf, int size, int rwflag, void *userdata);

// ============================================================================
// دوال ptrace الأصلية (تحميل ديناميكي)
// ============================================================================
#define PT_DENY_ATTACH 31
typedef int (*ptrace_ptr_t)(int, pid_t, caddr_t, int);
static ptrace_ptr_t real_ptrace = NULL;
static void load_real_ptrace(void) {
    if (!real_ptrace) {
        real_ptrace = (ptrace_ptr_t)dlsym(RTLD_DEFAULT, "ptrace");
    }
}

// ============================================================================
// مؤشرات الدوال الأصلية (fishhook)
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

// ============================================================================
// الدوال البديلة
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
static Boolean my_SecKeyVerifySignature(SecKeyRef key, SecKeyAlgorithm algorithm, CFDataRef dataToSign, CFDataRef signature, CFErrorRef *error) {
    return true;
}

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

// ============================================================================
// Swizzling Objective-C
// ============================================================================
static void swizzle_objc_methods() {
    Class deviceCls = objc_getClass("UIDevice");
    if (deviceCls) {
        Method m = class_getInstanceMethod(deviceCls, @selector(identifierForVendor));
        if (m) {
            method_setImplementation(m, imp_implementationWithBlock(^id(id self) {
                return [[NSUUID alloc] initWithUUIDString:@"00000000-0000-0000-0000-000000000000"];
            }));
        }
    }
    Class laContextCls = objc_getClass("LAContext");
    if (laContextCls) {
        Method m1 = class_getInstanceMethod(laContextCls, @selector(evaluatePolicy:localizedReason:reply:));
        if (m1) {
            method_setImplementation(m1, imp_implementationWithBlock(^(id self, LAPolicy policy, NSString *reason, void(^reply)(BOOL, NSError *)) {
                if (reply) reply(YES, nil);
            }));
        }
        Method m2 = class_getInstanceMethod(laContextCls, @selector(canEvaluatePolicy:error:));
        if (m2) {
            method_setImplementation(m2, imp_implementationWithBlock(^BOOL(id self, LAPolicy policy, NSError **error) {
                return YES;
            }));
        }
    }
}

// ============================================================================
// fishhook
// ============================================================================
static void fishhook_bindings() {
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
    };
    rebind_symbols(bindings, sizeof(bindings)/sizeof(bindings[0]));
}

// ============================================================================
// دوال البيئة (اختيارية – يمكن تفعيلها من الزر)
// ============================================================================
static void perform_security_checks() {
    // يمكنك تركها فارغة أو إضافة تحليلات دون قتل التطبيق
}

// ============================================================================
// بدء تشغيل الحماية (يتم استدعاؤها عند الضغط على الزر)
// ============================================================================
void start_antiban_protection(void) {
    load_real_ptrace();
    fishhook_bindings();
    swizzle_objc_methods();
    perform_security_checks();
    // ptrace anti-debug
    if (real_ptrace) real_ptrace(PT_DENY_ATTACH, 0, 0, 0);
}

// ============================================================================
// واجهة المستخدم (ViewController)
// ============================================================================
@interface ViewController ()
@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [UIColor systemBackgroundColor];

    // زر تشغيل الحماية
    UIButton *btn = [UIButton buttonWithType:UIButtonTypeSystem];
    [btn setTitle:@"تشغيل ANTIBAN" forState:UIControlStateNormal];
    btn.titleLabel.font = [UIFont boldSystemFontOfSize:24];
    btn.backgroundColor = [UIColor systemBlueColor];
    [btn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    btn.layer.cornerRadius = 12;
    btn.translatesAutoresizingMaskIntoConstraints = NO;
    [btn addTarget:self action:@selector(activateProtection) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:btn];

    [NSLayoutConstraint activateConstraints:@[
        [btn.centerXAnchor constraintEqualToAnchor:self.view.centerXAnchor],
        [btn.centerYAnchor constraintEqualToAnchor:self.view.centerYAnchor],
        [btn.widthAnchor constraintEqualToConstant:220],
        [btn.heightAnchor constraintEqualToConstant:60]
    ]];
}

- (void)activateProtection {
    start_antiban_protection();
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"تم بنجاح"
                                                                   message:@"تم تشغيل ANTIBAN"
                                                            preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"موافق" style:UIAlertActionStyleDefault handler:nil]];
    [self presentViewController:alert animated:YES completion:nil];
}

@end
