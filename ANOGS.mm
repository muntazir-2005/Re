// ============================================================================
// 完整稳定版反反调试/反越狱 Hook 库 (نسخة معدلة ومستقرة تماماً بدون أخطاء تجميع)
// 基于 fishhook (安全层) + Dobby (功能层) 双重保障，无崩溃，无需越狱
// ============================================================================

// 1. تضمين ملفات النظام الأساسية أولاً لمنع تعارض C++ Modules داخل dobby.h
#include <stdint.h>
#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <time.h>
#include <pthread.h>

// تعريفات يدوية لدوال النظام غير الموجودة في الـ iOS SDK الافتراضي لـ Theos
#define PT_DENY_ATTACH 31
extern "C" int ptrace(int request, pid_t pid, caddr_t addr, int data);
extern "C" int proc_pidpath(int pid, void *buffer, uint32_t buffersize);

#include <mach/mach.h>
#include <mach-o/dyld.h>
#include <TargetConditionals.h>
#include <sys/param.h>
#include <sys/mount.h>
#include <sys/utsname.h>
#include <CommonCrypto/CommonCryptor.h>
#include <Security/Security.h>
#include <Security/SecKey.h>
#include <objc/runtime.h>
#include <objc/message.h>
#include <LocalAuthentication/LocalAuthentication.h>

// 2. استدعاء ملفات الرأس للمكتبات الخارجية
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

// إعلان مسبق للدوال لمنع الـ compiler warnings
static int my_ptrace_dobby(int request, pid_t pid, caddr_t addr, int data);
static int my_sysctl_dobby(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen);
static int my_task_for_pid(mach_port_t target_tport, int pid, mach_port_t *tn);
static int my_vm_read_overwrite(vm_map_t target_task, vm_address_t address, vm_size_t size, vm_address_t data, vm_size_t *outsize);

// ============================================================================
// 第一层：鱼钩安全层 —— 在应用任何 Dobby Hook 之前，先强制禁用危险系统调用
// ============================================================================
static int (*orig_ptrace_safe)(int request, pid_t pid, caddr_t addr, int data);
static int my_ptrace_safe(int request, pid_t pid, caddr_t addr, int data) {
    if (request == PT_DENY_ATTACH) {
        return 0;
    }
    if (orig_ptrace_safe) return orig_ptrace_safe(request, pid, addr, data);
    return 0;
}

static int (*orig_sysctl_safe)(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen);
static int my_sysctl_safe(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    int ret = orig_sysctl_safe ? orig_sysctl_safe(name, namelen, oldp, oldlenp, newp, newlen) : 0;
    if (ret == 0 && oldp && namelen == 4 && name[0] == CTL_KERN && name[1] == KERN_PROC && name[2] == KERN_PROC_PID) {
        struct kinfo_proc *kp = (struct kinfo_proc *)oldp;
        kp->kp_proc.p_flag &= ~P_TRACED;
    }
    return ret;
}

__attribute__((constructor(101)))
static void initialize_fishhook_safety(void) {
    static int initialized = 0;
    if (initialized) return;
    initialized = 1;
    
    srand((unsigned int)time(NULL));
    
    struct rebinding rebindings[] = {
        {"ptrace", (void *)my_ptrace_safe, (void **)&orig_ptrace_safe},
        {"sysctl", (void *)my_sysctl_safe, (void **)&orig_sysctl_safe},
    };
    rebind_symbols(rebindings, sizeof(rebindings) / sizeof(struct rebinding));
    
    ptrace(PT_DENY_ATTACH, 0, 0, 0);
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

// OpenSSL (تم تبديل أنواع الهياكل المفقودة بمؤشرات void* لمنع الحاجة لملفات الرأس)
static int (*orig_RSA_verify)(int type, const unsigned char *m, unsigned int m_len, const unsigned char *sig, unsigned int sig_len, void *rsa);
static int (*orig_RSA_sign)(int type, const unsigned char *m, unsigned int m_len, unsigned char *sig, unsigned int *sig_len, void *rsa);
static int (*orig_EVP_PKEY_verify)(void *ctx, const unsigned char *sig, size_t sig_len, const unsigned char *tbs, size_t tbs_len);
static int (*orig_X509_verify_cert)(void *ctx);
static int (*orig_X509_check_private_key)(void *x509, void *pkey);
static void* (*orig_PEM_read_bio_PrivateKey)(void *bp, void **x, void *cb, void *u);
static int (*orig_SSL_CTX_use_PrivateKey_file)(void *ctx, const char *file, int type);
static int (*orig_SSL_CTX_check_private_key)(void *ctx);
static int (*orig_SSL_CTX_load_verify_locations)(void *ctx, const char *CAfile, const char *CApath);

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
    if (!name) return orig_sysctlbyname ? orig_sysctlbyname(name, oldp, oldlenp, newp, newlen) : -1;
    char buf[256];
    strncpy(buf, name, sizeof(buf)-1);
    buf[sizeof(buf)-1] = '\0';
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
    if (!symbol) return orig_dlsym ? orig_dlsym(handle, symbol) : NULL;
    char buf[256];
    strncpy(buf, symbol, sizeof(buf)-1);
    buf[sizeof(buf)-1] = '\0';
    obfuscate_str(buf);
    if (strstr(buf, "cgenpr") || strstr(buf, "flfpby") || strstr(buf, "gnfx_sbe_cvq") || strstr(buf, "iz_ernq")) {
        return NULL;
    }
    return orig_dlsym ? orig_dlsym(handle, symbol) : NULL;
}

static int my_task_for_pid(mach_port_t target_tport, int pid, mach_port_t *tn) {
    junk_code();
    return KERN_FAILURE;
}

static int my_vm_read_overwrite(vm_map_t target_task, vm_address_t address, vm_size_t size, vm_address_t data, vm_size_t *outsize) {
    junk_code();
    return KERN_FAILURE;
}

static int my_vm_write(vm_map_t target_task, vm_address_t address, vm_offset_t data, mach_msg_type_number_t dataCnt) {
    junk_code();
    return KERN_FAILURE;
}

static int my_vm_protect(vm_map_t target_task, vm_address_t address, vm_size_t size, boolean_t set_max, vm_prot_t new_protection) {
    junk_code();
    return orig_vm_protect ? orig_vm_protect(target_task, address, size, set_max, new_protection) : KERN_SUCCESS;
}

static int my_mach_vm_protect(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, boolean_t set_max, vm_prot_t new_protection) {
    junk_code();
    return orig_mach_vm_protect ? orig_mach_vm_protect(target_task, address, size, set_max, new_protection) : KERN_SUCCESS;
}

// Keychain
static OSStatus my_SecItemCopyMatching(CFDictionaryRef query, CFTypeRef *result) {
    junk_code();
    return errSecItemNotFound;
}

static OSStatus my_SecItemAdd(CFDictionaryRef attributes, CFTypeRef *result) {
    junk_code();
    return errSecDuplicateItem;
}

static OSStatus my_SecItemUpdate(CFDictionaryRef query, CFDictionaryRef attributesToUpdate) {
    junk_code();
    return errSecItemNotFound;
}

static OSStatus my_SecItemDelete(CFDictionaryRef query) {
    junk_code();
    return errSecSuccess;
}

static SecKeyRef my_SecKeyCreateRandomKey(CFDictionaryRef parameters, CFErrorRef *error) {
    junk_code();
    return NULL;
}

static SecKeyRef my_SecKeyCopyPublicKey(SecKeyRef key) {
    junk_code();
    return NULL;
}

static CFDataRef my_SecKeyCreateSignature(SecKeyRef key, SecKeyAlgorithm algorithm, CFDataRef dataToSign, CFErrorRef *error) {
    junk_code();
    return CFDataCreate(NULL, (const UInt8*)"fake_signature", 14);
}

static Boolean my_SecKeyVerifySignature(SecKeyRef key, SecKeyAlgorithm algorithm, CFDataRef dataToSign, CFDataRef signature, CFErrorRef *error) {
    junk_code();
    return true;
}

static CCCryptorStatus my_CCCrypt(CCOperation op, CCAlgorithm alg, CCOptions options, const void *key, size_t keyLength, const void *iv, const void *dataIn, size_t dataInLength, void *dataOut, size_t dataOutAvailable, size_t *dataOutMoved) {
    junk_code();
    if (dataOut && dataOutMoved) {
        memcpy(dataOut, dataIn, dataInLength);
        *dataOutMoved = dataInLength;
        return kCCSuccess;
    }
    return kCCSuccess;
}

// OpenSSL 替换 (总是返回成功)
static int my_RSA_verify(int type, const unsigned char *m, unsigned int m_len, const unsigned char *sig, unsigned int sig_len, void *rsa) {
    junk_code();
    return 1;
}
static int my_RSA_sign(int type, const unsigned char *m, unsigned int m_len, unsigned char *sig, unsigned int *sig_len, void *rsa) {
    junk_code();
    return 1;
}
static int my_EVP_PKEY_verify(void *ctx, const unsigned char *sig, size_t sig_len, const unsigned char *tbs, size_t tbs_len) {
    junk_code();
    return 1;
}
static int my_X509_verify_cert(void *ctx) {
    junk_code();
    return 1;
}
static int my_X509_check_private_key(void *x509, void *pkey) {
    junk_code();
    return 1;
}
static void* my_PEM_read_bio_PrivateKey(void *bp, void **x, void *cb, void *u) {
    junk_code();
    return NULL;
}
static int my_SSL_CTX_use_PrivateKey_file(void *ctx, const char *file, int type) {
    junk_code();
    return 1;
}
static int my_SSL_CTX_check_private_key(void *ctx) {
    junk_code();
    return 1;
}
static int my_SSL_CTX_load_verify_locations(void *ctx, const char *CAfile, const char *CApath) {
    junk_code();
    return 1;
}

// Jailbreak / Debug 检测函数替换
static bool my_is_jb(void) { junk_code(); return false; }
static bool my_ROOTED(void) { junk_code(); return false; }
static bool my_DEBUGGER_ATTACHED(void) { junk_code(); return false; }
static bool my_isDebuggerAttached(void) { junk_code(); return false; }
static bool my_checkJailbreak(void) { junk_code(); return false; }
static bool my_hasCydia(void) { junk_code(); return false; }
static bool my_isJailbroken_c(void) { junk_code(); return false; }
static bool my_amIBeingDebugged(void) { junk_code(); return false; }

// Obj-C 替换
static id my_UIDevice_identifierForVendor(id self, SEL _cmd) {
    junk_code();
    return [[NSUUID alloc] initWithUUIDString:@"00000000-0000-0000-0000-000000000000"];
}

static void my_LAContext_evaluatePolicy(id self, SEL _cmd, LAPolicy policy, NSString *localizedReason, id reply) {
    junk_code();
    void (^replyBlock)(BOOL success, NSError *error) = (void (^)(BOOL, NSError *))reply;
    if (replyBlock) {
        replyBlock(YES, nil);
    }
}

static BOOL my_LAContext_canEvaluatePolicy(id self, SEL _cmd, LAPolicy policy, NSError **error) {
    junk_code();
    return YES;
}

// ============================================================================
// 通用 Hook 辅助: 先找符号，再用 DobbyHook
// ============================================================================
static void stealth_hook(const char *obf_name, void *replacement, void **original) {
    char real_name[256];
    strncpy(real_name, obf_name, sizeof(real_name)-1);
    real_name[sizeof(real_name)-1] = '\0';
    obfuscate_str(real_name); 
    void *sym = dlsym(RTLD_DEFAULT, real_name);
    if (sym) {
        DobbyHook(sym, replacement, original);
    }
}

// ============================================================================
// 环境检测函数
// ============================================================================
static int is_simulator(void) {
    junk_code();
#if TARGET_IPHONE_SIMULATOR
    return 1;
#else
    struct utsname systemInfo;
    uname(&systemInfo);
    return (strcmp(systemInfo.machine, "x86_64") == 0 || strcmp(systemInfo.machine, "i386") == 0);
#endif
}

static int is_jailbroken_paths(void) {
    junk_code();
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
    for (int i = 0; paths[i]; i++) {
        if (access(paths[i], F_OK) == 0) return 1;
    }
    return 0;
}

static int is_cydia_installed(void) {
    junk_code();
#if TARGET_OS_IPHONE
    Class ls = objc_getClass("LSApplicationWorkspace");
    if (ls) {
        id workspace = ((id (*)(id, SEL))objc_msgSend)(ls, sel_registerName("defaultWorkspace"));
        if (workspace) {
            int ret = ((int (*)(id, SEL, id))objc_msgSend)(workspace, sel_registerName("openApplicationWithBundleID:"), @"com.saurik.Cydia");
            return ret;
        }
    }
#endif
    return 0;
}

static int is_dyld_hijacked(void) {
    return (getenv("DYLD_INSERT_LIBRARIES") != NULL) || (getenv("DYLD_FORCE_FLAT_NAMESPACE") != NULL);
}

static int is_debugger_attached(void) {
    int name[4];
    struct kinfo_proc info;
    size_t info_size = sizeof(info);
    name[0] = CTL_KERN;
    name[1] = KERN_PROC;
    name[2] = KERN_PROC_PID;
    name[3] = getpid();
    if (sysctl(name, 4, &info, &info_size, NULL, 0) == -1) return 0;
    return (info.kp_proc.p_flag & P_TRACED) != 0;
}

static int ptrace_deny_attach(void) {
    return (ptrace(PT_DENY_ATTACH, 0, 0, 0) == -1);
}

static int is_substrate_loaded(void) {
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char *name = _dyld_get_image_name(i);
        if (!name) continue;
        char buf[256];
        strncpy(buf, name, sizeof(buf)-1);
        buf[sizeof(buf)-1] = '\0';
        obfuscate_str(buf);
        if (strstr(buf, "ZbovyrFhofgengr") || strstr(buf, "Fhofgengr") || strstr(buf, "PlqvnFhofgengr"))
            return 1;
    }
    return 0;
}

static int is_ssh_running(void) { return access("/usr/sbin/sshd", F_OK) == 0; }
static int is_apt_installed(void) { return access("/etc/apt", F_OK) == 0; }
static int is_frida_installed(void) { return access("/usr/sbin/frida-server", F_OK) == 0; }
static int is_debugserver_installed(void) { return access("/Developer/usr/bin/debugserver", F_OK) == 0; }

static int check_provisioning(void) {
    uint32_t size = 0;
    _NSGetExecutablePath(NULL, &size);
    if (size == 0) return 0;
    
    char *execPath = (char *)malloc(size);
    _NSGetExecutablePath(execPath, &size);
    char *lastSlash = strrchr(execPath, '/');
    if (lastSlash) {
        *lastSlash = '\0';
        char path[MAXPATHLEN];
        snprintf(path, sizeof(path), "%s/embedded.mobileprovision", execPath);
        FILE *fp = fopen(path, "r");
        if (fp) {
            fseek(fp, 0, SEEK_END);
            long len = ftell(fp);
            fseek(fp, 0, SEEK_SET);
            char *data = (char*)malloc(len + 1);
            size_t read_bytes = fread(data, 1, len, fp);
            fclose(fp);
            data[read_bytes] = '\0';
            int debuggable = (strstr(data, "<key>get-task-allow</key><true/>") != NULL);
            free(data);
            free(execPath);
            return debuggable;
        }
    }
    free(execPath);
    return 0;
}

static int check_env(void) {
    const char *vars[] = {"DYLD_PRINT_TO_FILE", "DYLD_INSERT_LIBRARIES", "CFNETWORK_DIAGNOSTICS", "OBJC_DISABLE_VALIDATION", NULL};
    for (int i = 0; vars[i]; i++) if (getenv(vars[i]) != NULL) return 1;
    return 0;
}

static int check_ppid(void) {
    pid_t ppid = getppid();
    char pathbuf[4096];
    if (proc_pidpath(ppid, pathbuf, sizeof(pathbuf)) > 0) {
        char buf[256];
        strncpy(buf, pathbuf, sizeof(buf)-1);
        buf[sizeof(buf)-1] = '\0';
        obfuscate_str(buf);
        if (strstr(buf, "qrohtfreire") || strstr(buf, "yyqo")) return 1;
    }
    return 0;
}

static int is_frida_loaded(void) {
    return (dlopen("frida-agent.dylib", RTLD_NOLOAD) != NULL);
}

static void perform_security_checks(void) {
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
        printf("[!] Threat level high (%d), but hooks are active. Not exiting.\n", threat_level);
    } else if (threat_level > 20) {
        printf("[*] Threat level medium (%d).\n", threat_level);
    }
}

// ============================================================================
// 主 Hook 函数 (由第二层 constructor 调用)
// ============================================================================
static void hook_all_functions(void) {
    stealth_hook("cgenpr", (void*)my_ptrace_dobby, (void**)&orig_ptrace);
    stealth_hook("flfpby", (void*)my_sysctl_dobby, (void**)&orig_sysctl);
    stealth_hook("flfpbyolanzr", (void*)my_sysctlbyname, (void**)&orig_sysctlbyname);
    stealth_hook("qybcra", (void*)my_dlopen, (void**)&orig_dlopen);
    stealth_hook("qyflz", (void*)my_dlsym, (void**)&orig_dlsym);
    stealth_hook("gnfx_sbe_cvq", (void*)my_task_for_pid, (void**)&orig_task_for_pid);
    stealth_hook("iz_ernq_birejevgr", (void*)my_vm_read_overwrite, (void**)&orig_vm_read_overwrite);
    stealth_hook("iz_jevgr", (void*)my_vm_write, (void**)&orig_vm_write);
    stealth_hook("iz_cebgrpg", (void*)my_vm_protect, (void**)&orig_vm_protect);
    stealth_hook("znpu_iz_cebgrpg", (void*)my_mach_vm_protect, (void**)&orig_mach_vm_protect);

    // Keychain
    stealth_hook("FrpVgrzPbclZngpuvat", (void*)my_SecItemCopyMatching, (void**)&orig_SecItemCopyMatching);
    stealth_hook("FrpVgrzNqq", (void*)my_SecItemAdd, (void**)&orig_SecItemAdd);
    stealth_hook("FrpVgrzHcqngr", (void*)my_SecItemUpdate, (void**)&orig_SecItemUpdate);
    stealth_hook("FrpVgrzQryrgr", (void*)my_SecItemDelete, (void**)&orig_SecItemDelete);

    // SecKey
    stealth_hook("FrpXrlPerngrEnaqbzXrl", (void*)my_SecKeyCreateRandomKey, (void**)&orig_SecKeyCreateRandomKey);
    stealth_hook("FrpXrlPbclChoyvpXrl", (void*)my_SecKeyCopyPublicKey, (void**)&orig_SecKeyCopyPublicKey);
    stealth_hook("FrpXrlPerngrFvtangher", (void*)my_SecKeyCreateSignature, (void**)&orig_SecKeyCreateSignature);
    stealth_hook("FrpXrlIrevslFvtangher", (void*)my_SecKeyVerifySignature, (void**)&orig_SecKeyVerifySignature);

    // CommonCrypto
    stealth_hook("PPPelcg", (void*)my_CCCrypt, (void**)&orig_CCCrypt);

    // OpenSSL Hooks
    stealth_hook("ENF_irevsl", (void*)my_RSA_verify, (void**)&orig_RSA_verify);
    stealth_hook("ENF_fvta", (void*)my_RSA_sign, (void**)&orig_RSA_sign);
    stealth_hook("RUC_XRL_irevsl", (void*)my_EVP_PKEY_verify, (void**)&orig_EVP_PKEY_verify);
    stealth_hook("K509_irevsl_preg", (void*)my_X509_verify_cert, (void**)&orig_X509_verify_cert);
    stealth_hook("K509_purpx_cevingr_xrl", (void*)my_X509_check_private_key, (void**)&orig_X509_check_private_key);
    stealth_hook("CRZ_ernq_ovb_CevngrXrl", (void*)my_PEM_read_bio_PrivateKey, (void**)&orig_PEM_read_bio_PrivateKey);
    stealth_hook("FFY_PGK_hfr_CevngrXrl_svyr", (void*)my_SSL_CTX_use_PrivateKey_file, (void**)&orig_SSL_CTX_use_PrivateKey_file);
    stealth_hook("FFY_PGK_purpx_cevingr_xrl", (void*)my_SSL_CTX_check_private_key, (void**)&orig_SSL_CTX_check_private_key);
    stealth_hook("FFY_PGK_ybnq_irevsl_ybpngvbaf", (void*)my_SSL_CTX_load_verify_locations, (void**)&orig_SSL_CTX_load_verify_locations);

    // Jailbreak 检测函数
    const char *jb_funcs[] = {"vf_wo", "EBBGRQ", "QRHTTRE_NGGNPURQ", "vfQrhttreNggnpurq", "purpxWnvyoernx", "unfPlqvn", "vfWnvyoernx", "nzVOrvatQrhttrq"};
    void *jb_repl[] = {(void*)my_is_jb, (void*)my_ROOTED, (void*)my_DEBUGGER_ATTACHED, (void*)my_isDebuggerAttached,
                       (void*)my_checkJailbreak, (void*)my_hasCydia, (void*)my_isJailbroken_c, (void*)my_amIBeingDebugged};
    void **jb_orig[] = {(void**)&orig_is_jb, (void**)&orig_ROOTED, (void**)&orig_DEBUGGER_ATTACHED,
                        (void**)&orig_isDebuggerAttached, (void**)&orig_checkJailbreak, (void**)&orig_hasCydia,
                        (void**)&orig_isJailbroken, (void**)&orig_amIBeingDebugged};
    for (int i = 0; i < 8; i++) {
        char real_name[256];
        strncpy(real_name, jb_funcs[i], sizeof(real_name)-1);
        real_name[sizeof(real_name)-1] = '\0';
        obfuscate_str(real_name);
        void *sym = dlsym(RTLD_DEFAULT, real_name);
        if (sym) DobbyHook(sym, jb_repl[i], jb_orig[i]);
    }

    // Objective-C Hooks
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
        SEL selEval = @selector(evaluatePolicy:localizedReason:reply:);
        Method mEval = class_getInstanceMethod(laContextCls, selEval);
        if (mEval) {
            orig_LAContext_evaluatePolicy = method_getImplementation(mEval);
            method_setImplementation(mEval, (IMP)my_LAContext_evaluatePolicy);
        }
        SEL selCan = @selector(canEvaluatePolicy:error:);
        Method mCan = class_getInstanceMethod(laContextCls, selCan);
        if (mCan) {
            orig_LAContext_canEvaluatePolicy = method_getImplementation(mCan);
            method_setImplementation(mCan, (IMP)my_LAContext_canEvaluatePolicy);
        }
    }
}

// ============================================================================
// 第二层 Constructor: Dobby 层初始化，确保安全层已经稳定运行
// ============================================================================
__attribute__((constructor(102)))
static void initialize_dobby_hooks(void) {
    usleep(50000); // 50ms
    perform_security_checks();
    hook_all_functions();
}
