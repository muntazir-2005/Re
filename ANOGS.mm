// ============================================================================
// 完整稳定版反反调试/反越狱 Hook 库
// 基于 fishhook (安全层) + Dobby (功能层) 双重保障，无崩溃，无需越狱
// ============================================================================

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <sys/stat.h>
#include <sys/sysctl.h> // تم الإضافة: لإصلاح هياكل sysctl و kinfo_proc
#include <sys/types.h>

// تعريف يدوي لدالة ptrace والثوابت المطلوبة (غير موجودة في iOS SDK)
#define PT_DENY_ATTACH 31
#ifdef __cplusplus
extern "C" {
#endif
    int ptrace(int request, pid_t pid, caddr_t addr, int data);
#ifdef __cplusplus
}
#endif

// تم الحذف: #include <sys/ptrace.h> لتجنب خطأ الملف المفقود

#include <mach/mach.h>
#include <mach-o/dyld.h>
#include <TargetConditionals.h>
#include <sys/param.h>
#include <sys/mount.h>
#include <sys/utsname.h>
#include <CommonCrypto/CommonCryptor.h>
#include <Security/Security.h>
#include <Security/SecKey.h>
#include <time.h>
#include <pthread.h>
#include <objc/runtime.h>
#include <objc/message.h>
#include <LocalAuthentication/LocalAuthentication.h>

// تم الإضافة: تعريف مسبق لهياكل OpenSSL لكي يتم التجميع بدون الحاجة لملفات headers خارجية
typedef struct rsa_st RSA;
typedef struct evp_pkey_ctx_st EVP_PKEY_CTX;
typedef struct x509_store_ctx_st X509_STORE_CTX;
typedef struct x509_st X509;
typedef struct evp_pkey_st EVP_PKEY;
typedef struct bio_st BIO;
typedef struct ssl_ctx_st SSL_CTX;
typedef int (*pem_password_cb)(char *buf, int size, int rwflag, void *u);

// 第三方库头文件
#include "fishhook.h"
#include "dobby.h"

// ============================================================================
// 线程安全锁
// ============================================================================
static pthread_mutex_t g_hookMutex = PTHREAD_MUTEX_INITIALIZER;

// ============================================================================
// 基础辅助函数 (混淆 + 垃圾代码)
// ============================================================================
static inline void obfuscate_str(char *s) {
    while (*s) {
        if ((*s >= 'a' && *s <= 'z') || (*s >= 'A' && *s <= 'Z')) {
            if ((*s >= 'a' && *s <= 'm') || (*s >= 'A' && *s <= 'M'))
                *s += 13;
            else
                *s -= 13;
        }
        s++;
    }
}

#define OBF(s) obfuscate_str((char[])s)

static inline void junk_code(void) {
    volatile int a = rand() % 100;
    volatile int b = rand() % 100;
    volatile int c = a * b + a - b;
    (void)c;
}

// ============================================================================
// 第一层：鱼钩安全层 —— 在应用任何 Dobby Hook 之前，先强制禁用危险系统调用
// ============================================================================

// ptrace 替换
static int (*orig_ptrace_safe)(int request, pid_t pid, caddr_t addr, int data);
static int my_ptrace_safe(int request, pid_t pid, caddr_t addr, int data) {
    if (request == PT_DENY_ATTACH) {
        return 0; // 完全忽略 PT_DENY_ATTACH，防止应用自杀
    }
    if (orig_ptrace_safe) return orig_ptrace_safe(request, pid, addr, data);
    return 0;
}

// sysctl 替换 (清除 P_TRACED 标志)
static int (*orig_sysctl_safe)(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen);
static int my_sysctl_safe(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    int ret = orig_sysctl_safe ? orig_sysctl_safe(name, namelen, oldp, oldlenp, newp, newlen) : 0;
    if (ret == 0 && oldp && namelen == 4 && name[0] == CTL_KERN && name[1] == KERN_PROC && name[2] == KERN_PROC_PID) {
        struct kinfo_proc *kp = (struct kinfo_proc *)oldp;
        kp->kp_proc.p_flag &= ~P_TRACED;
    }
    return ret;
}

// ============================================================================
// 原函数指针 (完整列表，供 Dobby 层使用)
// ============================================================================
static int (*orig_printf)(const char *format, ...);
static int (*orig_ptrace)(int request, pid_t pid, caddr_t addr, int data);
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

// Jailbreak / Debug 检测 C 函数
static bool (*orig_is_jb)(void);
static bool (*orig_ROOTED)(void);
static bool (*orig_DEBUGGER_ATTACHED)(void);
static bool (*orig_isDebuggerAttached)(void);
static bool (*orig_checkJailbreak)(void);
static bool (*orig_hasCydia)(void);
static bool (*orig_isJailbroken)(void);
static bool (*orig_amIBeingDebugged)(void);

// Obj-C 原始方法
static IMP orig_UIDevice_identifierForVendor;
static IMP orig_LAContext_evaluatePolicy;
static IMP orig_LAContext_canEvaluatePolicy;

// ============================================================================
// 替换函数 (Dobby 层)
// ============================================================================
static int my_ptrace_dobby(int request, pid_t pid, caddr_t addr, int data) {
    junk_code();
    if (request == PT_DENY_ATTACH) return 0;
    return orig_ptrace ? orig_ptrace(request, pid, addr, data) : 0;
}

static int my_sysctl_dobby(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    junk_code();
    int ret = orig_sysctl ? orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen) : 0;
    if (ret == 0 && oldp && namelen == 4 && name[0] == CTL_KERN && name[1] == KERN_PROC && name[2] == KERN_PROC_PID) {
        struct kinfo_proc *kp = (struct kinfo_proc *)oldp;
        kp->kp_proc.p_flag &= ~P_TRACED;
    }
    return ret;
}

static int my_sysctlbyname(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    junk_code();
    char buf[256];
    strncpy(buf, name, sizeof(buf)-1);
    obfuscate_str(buf);
    if (strstr(buf, "qroht") || strstr(buf, "xrea.cebp")) {
        if (oldp && oldlenp) {
            memset(oldp, 0, *oldlenp);
            return 0;
        }
    }
    return orig_sysctlbyname ? orig_sysctlbyname(name, oldp, oldlenp, newp, newlen) : 0;
}

static void* my_dlopen(const char *path, int mode) {
    junk_code();
    return orig_dlopen ? orig_dlopen(path, mode) : NULL;
}

static void* my_dlsym(void *handle, const char *symbol) {
    junk_code();
    char buf[256];
    strncpy(buf, symbol, sizeof(buf)-1);
    obfuscate_str(buf);
    if (strstr(buf, "cgenpr") || strstr(buf, "flfpby") || strstr(buf, "gnfx_sbe_cvq") || strstr(buf, "iz_ernq")) {
        return NULL;
    }
    return orig_dlsym ? orig_dlsym(handle, symbol) : NULL;
}

static int my_task_for_pid(mach_port_t target_tport, int pid, mach_port_t *tn) { junk_code(); return KERN_FAILURE; }
static int my_vm_read_overwrite(vm_map_t target_task, vm_address_t address, vm_size_t size, vm_address_t data, vm_size_t *outsize) { junk_code(); return KERN_FAILURE; }
static int my_vm_write(vm_map_t target_task, vm_address_t address, vm_offset_t data, mach_msg_type_number_t dataCnt) { junk_code(); return KERN_FAILURE; }
static int my_vm_protect(vm_map_t target_task, vm_address_t address, vm_size_t size, boolean_t set_max, vm_prot_t new_protection) {
    junk_code();
    return orig_vm_protect ? orig_vm_protect(target_task, address, size, set_max, new_protection) : KERN_SUCCESS;
}
static int my_mach_vm_protect(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, boolean_t set_max, vm_prot_t new_protection) {
    junk_code();
    return orig_mach_vm_protect ? orig_mach_vm_protect(target_task, address, size, set_max, new_protection) : KERN_SUCCESS;
}

// Keychain
static OSStatus my_SecItemCopyMatching(CFDictionaryRef query, CFTypeRef *result) { junk_code(); return errSecItemNotFound; }
static OSStatus my_SecItemAdd(CFDictionaryRef attributes, CFTypeRef *result) { junk_code(); return errSecDuplicateItem; }
static OSStatus my_SecItemUpdate(CFDictionaryRef query, CFDictionaryRef attributesToUpdate) { junk_code(); return errSecItemNotFound; }
static OSStatus my_SecItemDelete(CFDictionaryRef query) { junk_code(); return errSecSuccess; }

static SecKeyRef my_SecKeyCreateRandomKey(CFDictionaryRef parameters, CFErrorRef *error) { junk_code(); return NULL; }
static SecKeyRef my_SecKeyCopyPublicKey(SecKeyRef key) { junk_code(); return NULL; }
static CFDataRef my_SecKeyCreateSignature(SecKeyRef key, SecKeyAlgorithm algorithm, CFDataRef dataToSign, CFErrorRef *error) {
    junk_code();
    return CFDataCreate(NULL, (const UInt8*)"fake_signature", 14);
}
static Boolean my_SecKeyVerifySignature(SecKeyRef key, SecKeyAlgorithm algorithm, CFDataRef dataToSign, CFDataRef signature, CFErrorRef *error) { junk_code(); return true; }

static CCCryptorStatus my_CCCrypt(CCOperation op, CCAlgorithm alg, CCOptions options, const void *key, size_t keyLength, const void *iv, const void *dataIn, size_t dataInLength, void *dataOut, size_t dataOutAvailable, size_t *dataOutMoved) {
    junk_code();
    if (dataOut && dataOutMoved) {
        memcpy(dataOut, dataIn, dataInLength);
        *dataOutMoved = dataInLength;
    }
    return kCCSuccess;
}

// OpenSSL
static int my_RSA_verify(int type, const unsigned char *m, unsigned int m_len, const unsigned char *sig, unsigned int sig_len, RSA *rsa) { junk_code(); return 1; }
static int my_RSA_sign(int type, const unsigned char *m, unsigned int m_len, unsigned char *sig, unsigned int *sig_len, RSA *rsa) { junk_code(); return 1; }
static int my_EVP_PKEY_verify(EVP_PKEY_CTX *ctx, const unsigned char *sig, size_t sig_len, const unsigned char *tbs, size_t tbs_len) { junk_code(); return 1; }
static int my_X509_verify_cert(X509_STORE_CTX *ctx) { junk_code(); return 1; }
static int my_X509_check_private_key(X509 *x509, EVP_PKEY *pkey) { junk_code(); return 1; }
static EVP_PKEY* my_PEM_read_bio_PrivateKey(BIO *bp, EVP_PKEY **x, pem_password_cb *cb, void *u) { junk_code(); return NULL; }
static int my_SSL_CTX_use_PrivateKey_file(SSL_CTX *ctx, const char *file, int type) { junk_code(); return 1; }
static int my_SSL_CTX_check_private_key(SSL_CTX *ctx) { junk_code(); return 1; }
static int my_SSL_CTX_load_verify_locations(SSL_CTX *ctx, const char *CAfile, const char *CApath) { junk_code(); return 1; }

// 检测函数替换
static bool my_is_jb(void) { junk_code(); return false; }
static bool my_ROOTED(void) { junk_code(); return false; }
static bool my_DEBUGGER_ATTACHED(void) { junk_code(); return false; }
static bool my_isDebuggerAttached(void) { junk_code(); return false; }
static bool my_checkJailbreak(void) { junk_code(); return false; }
static bool my_hasCydia(void) { junk_code(); return false; }
static bool my_isJailbroken_c(void) { junk_code(); return false; }
static bool my_amIBeingDebugged(void) { junk_code(); return false; }

// Obj-C
static id my_UIDevice_identifierForVendor(id self, SEL _cmd) {
    junk_code();
    return [[NSUUID alloc] initWithUUIDString:@"00000000-0000-0000-0000-000000000000"];
}
static void my_LAContext_evaluatePolicy(id self, SEL _cmd, LAPolicy policy, id reply) {
    junk_code();
    void (^replyBlock)(BOOL success, NSError *error) = reply;
    replyBlock(YES, nil);
}
static BOOL my_LAContext_canEvaluatePolicy(id self, SEL _cmd, LAPolicy policy, NSError **error) { junk_code(); return YES; }

static void stealth_hook(const char *obf_name, void *replacement, void **original) {
    char real_name[256];
    strncpy(real_name, obf_name, sizeof(real_name)-1);
    obfuscate_str(real_name);
    void *sym = dlsym(RTLD_DEFAULT, real_name);
    if (sym) {
        DobbyHook(sym, replacement, original);
    }
}

// 环境检测
static int is_simulator(void) {
#if TARGET_IPHONE_SIMULATOR
    return 1;
#else
    struct utsname systemInfo;
    uname(&systemInfo);
    return (strcmp(systemInfo.machine, "x86_64") == 0 || strcmp(systemInfo.machine, "i386") == 0);
#endif
}

static int is_jailbroken_paths(void) {
    const char *paths[] = {"/Applications/Cydia.app", "/Library/MobileSubstrate/MobileSubstrate.dylib", "/bin/bash", "/usr/sbin/sshd", "/etc/apt", NULL};
    for (int i = 0; paths[i]; i++) { if (access(paths[i], F_OK) == 0) return 1; }
    return 0;
}

static void perform_security_checks(void) { junk_code(); }

static void hook_all_functions(void) {
    stealth_hook("cgenpr", (void*)my_ptrace_dobby, (void**)&orig_ptrace);
    stealth_hook("flfpby", (void*)my_sysctl_dobby, (void**)&orig_sysctl);
    stealth_hook("flfpbyolanzr", (void*)my_sysctlbyname, (void**)&orig_sysctlbyname);
    stealth_hook("qybcra", (void*)my_dlopen, (void**)&orig_dlopen);
    stealth_hook("qyflz", (void*)my_dlsym, (void**)&orig_dlsym);
    stealth_hook("gnfx_sbe_cvq", (void*)my_task_for_pid, (void**)&orig_task_for_pid);

    // Keychain / SecKey / CommonCrypto
    stealth_hook("FrpVgrzPbclZngpuvat", (void*)my_SecItemCopyMatching, (void**)&orig_SecItemCopyMatching);
    stealth_hook("FrpVgrzNqq", (void*)my_SecItemAdd, (void**)&orig_SecItemAdd);
    stealth_hook("FrpVgrzHcqngr", (void*)my_SecItemUpdate, (void**)&orig_SecItemUpdate);
    stealth_hook("FrpVgrzQryrgr", (void*)my_SecItemDelete, (void**)&orig_SecItemDelete);
    stealth_hook("PPPelcg", (void*)my_CCCrypt, (void**)&orig_CCCrypt);

    // OpenSSL Hooks
    stealth_hook("ENF_irevsl", (void*)my_RSA_verify, (void**)&orig_RSA_verify);
    stealth_hook("ENF_fvta", (void*)my_RSA_sign, (void**)&orig_RSA_sign);

    // Obj-C Hooks
    Class deviceCls = objc_getClass("UIDevice");
    if (deviceCls) {
        Method m = class_getInstanceMethod(deviceCls, @selector(identifierForVendor));
        if (m) method_setImplementation(m, (IMP)my_UIDevice_identifierForVendor);
    }
    Class laContextCls = objc_getClass("LAContext");
    if (laContextCls) {
        Method mEval = class_getInstanceMethod(laContextCls, @selector(evaluatePolicy:localizedReason:reply:));
        if (mEval) method_setImplementation(mEval, (IMP)my_LAContext_evaluatePolicy);
    }
}

// ============================================================================
// دالة التشغيل الموحدة والمثالية لملفات الـ dylib المستقلة
// ============================================================================
__attribute__((constructor))
static void initialize_dylib_extension(void) {
    static int initialized = 0;
    if (initialized) return;
    initialized = 1;
    
    srand((unsigned int)time(NULL));
    
    // تطبيق حماية fishhook الأساسية فوراً عند الحقن في الذاكرة
    struct rebinding rebindings[] = {
        {"ptrace", (void *)my_ptrace_safe, (void **)&orig_ptrace_safe},
        {"sysctl", (void *)my_sysctl_safe, (void **)&orig_sysctl_safe},
    };
    rebind_symbols(rebindings, sizeof(rebindings) / sizeof(struct rebinding));
    
    ptrace(PT_DENY_ATTACH, 0, 0, 0);
    
    // تأخير قصير جداً لضمان ثبات العناوين، ثم تطبيق خطافات Dobby
    usleep(10000); 
    hook_all_functions();
}
