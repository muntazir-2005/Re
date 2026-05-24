//  ANOGS.mm – final clean build with Theos
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

// ptrace dynamic loading
#define PT_DENY_ATTACH 31
typedef int (*ptrace_ptr_t)(int, pid_t, caddr_t, int);
static ptrace_ptr_t real_ptrace = NULL;
static void load_real_ptrace(void) {
    if (!real_ptrace) real_ptrace = (ptrace_ptr_t)dlsym(RTLD_DEFAULT, "ptrace");
}

// OpenSSL forward declarations
typedef struct rsa_st RSA;
typedef struct evp_pkey_st EVP_PKEY;
typedef struct evp_pkey_ctx_st EVP_PKEY_CTX;
typedef struct x509_st X509;
typedef struct X509_store_ctx_st X509_STORE_CTX;
typedef struct ssl_ctx_st SSL_CTX;
typedef struct bio_st BIO;
typedef int pem_password_cb(char *buf, int size, int rwflag, void *userdata);

// Original function pointers (used in fishhook)
static int (*orig_sysctl)(int *, u_int, void *, size_t *, void *, size_t);
static int (*orig_sysctlbyname)(const char *, void *, size_t *, void *, size_t);
static void* (*orig_dlopen)(const char *, int);
static void* (*orig_dlsym)(void *, const char *);
static int (*orig_task_for_pid)(mach_port_t, int, mach_port_t *);
static int (*orig_vm_read_overwrite)(vm_map_t, vm_address_t, vm_size_t, vm_address_t, vm_size_t *);
static int (*orig_vm_write)(vm_map_t, vm_address_t, vm_offset_t, mach_msg_type_number_t);
static int (*orig_vm_protect)(vm_map_t, vm_address_t, vm_size_t, boolean_t, vm_prot_t);
static int (*orig_mach_vm_protect)(vm_map_t, mach_vm_address_t, mach_vm_size_t, boolean_t, vm_prot_t);
static OSStatus (*orig_SecItemCopyMatching)(CFDictionaryRef, CFTypeRef *);
static OSStatus (*orig_SecItemAdd)(CFDictionaryRef, CFTypeRef *);
static OSStatus (*orig_SecItemUpdate)(CFDictionaryRef, CFDictionaryRef);
static OSStatus (*orig_SecItemDelete)(CFDictionaryRef);
static SecKeyRef (*orig_SecKeyCreateRandomKey)(CFDictionaryRef, CFErrorRef *);
static SecKeyRef (*orig_SecKeyCopyPublicKey)(SecKeyRef);
static CFDataRef (*orig_SecKeyCreateSignature)(SecKeyRef, SecKeyAlgorithm, CFDataRef, CFErrorRef *);
static Boolean (*orig_SecKeyVerifySignature)(SecKeyRef, SecKeyAlgorithm, CFDataRef, CFDataRef, CFErrorRef *);
static CCCryptorStatus (*orig_CCCrypt)(CCOperation, CCAlgorithm, CCOptions, const void *, size_t, const void *, const void *, size_t, void *, size_t, size_t *);
static int (*orig_RSA_verify)(int, const unsigned char *, unsigned int, const unsigned char *, unsigned int, RSA *);
static int (*orig_RSA_sign)(int, const unsigned char *, unsigned int, unsigned char *, unsigned int *, RSA *);
static int (*orig_EVP_PKEY_verify)(EVP_PKEY_CTX *, const unsigned char *, size_t, const unsigned char *, size_t);
static int (*orig_X509_verify_cert)(X509_STORE_CTX *);
static int (*orig_X509_check_private_key)(X509 *, EVP_PKEY *);
static EVP_PKEY* (*orig_PEM_read_bio_PrivateKey)(BIO *, EVP_PKEY **, pem_password_cb *, void *);
static int (*orig_SSL_CTX_use_PrivateKey_file)(SSL_CTX *, const char *, int);
static int (*orig_SSL_CTX_check_private_key)(SSL_CTX *);
static int (*orig_SSL_CTX_load_verify_locations)(SSL_CTX *, const char *, const char *);

// Hook functions (used in fishhook)
static int my_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    int ret = orig_sysctl ? orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen) : 0;
    if (ret == 0 && oldp && namelen == 4 && name[0]==CTL_KERN && name[1]==KERN_PROC && name[2]==KERN_PROC_PID) {
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
static void* my_dlopen(const char *path, int mode) { return orig_dlopen ? orig_dlopen(path, mode) : NULL; }
static void* my_dlsym(void *handle, const char *symbol) {
    if (symbol && (strstr(symbol,"ptrace")||strstr(symbol,"sysctl")||strstr(symbol,"task_for_pid")||strstr(symbol,"vm_read")))
        return NULL;
    return orig_dlsym ? orig_dlsym(handle, symbol) : NULL;
}
static int my_task_for_pid(mach_port_t t, int pid, mach_port_t *tn) { return KERN_FAILURE; }
static int my_vm_read_overwrite(vm_map_t t, vm_address_t a, vm_size_t s, vm_address_t d, vm_size_t *o) { return KERN_FAILURE; }
static int my_vm_write(vm_map_t t, vm_address_t a, vm_offset_t d, mach_msg_type_number_t c) { return KERN_FAILURE; }
static int my_vm_protect(vm_map_t t, vm_address_t a, vm_size_t s, boolean_t m, vm_prot_t p) {
    return orig_vm_protect ? orig_vm_protect(t,a,s,m,p) : KERN_SUCCESS;
}
static int my_mach_vm_protect(vm_map_t t, mach_vm_address_t a, mach_vm_size_t s, boolean_t m, vm_prot_t p) {
    return orig_mach_vm_protect ? orig_mach_vm_protect(t,a,s,m,p) : KERN_SUCCESS;
}
static OSStatus my_SecItemCopyMatching(CFDictionaryRef q, CFTypeRef *r) { return errSecItemNotFound; }
static OSStatus my_SecItemAdd(CFDictionaryRef a, CFTypeRef *r) { return errSecDuplicateItem; }
static OSStatus my_SecItemUpdate(CFDictionaryRef q, CFDictionaryRef a) { return errSecItemNotFound; }
static OSStatus my_SecItemDelete(CFDictionaryRef q) { return errSecSuccess; }
static SecKeyRef my_SecKeyCreateRandomKey(CFDictionaryRef p, CFErrorRef *e) { return NULL; }
static SecKeyRef my_SecKeyCopyPublicKey(SecKeyRef k) { return NULL; }
static CFDataRef my_SecKeyCreateSignature(SecKeyRef k, SecKeyAlgorithm a, CFDataRef d, CFErrorRef *e) {
    return CFDataCreate(NULL, (const UInt8*)"fake_signature", 14);
}
static Boolean my_SecKeyVerifySignature(SecKeyRef k, SecKeyAlgorithm a, CFDataRef d, CFDataRef s, CFErrorRef *e) { return true; }
static CCCryptorStatus my_CCCrypt(CCOperation op, CCAlgorithm alg, CCOptions opt,
                                  const void *key, size_t kl, const void *iv,
                                  const void *in, size_t inLen,
                                  void *out, size_t outAvail, size_t *moved) {
    if (!out || !moved) return kCCParamError;
    size_t bytes = (inLen < outAvail) ? inLen : outAvail;
    memcpy(out, in, bytes);
    *moved = bytes;
    return (bytes == inLen) ? kCCSuccess : kCCBufferTooSmall;
}
static int my_RSA_verify(int t, const unsigned char *m, unsigned int ml, const unsigned char *s, unsigned int sl, RSA *r) { return 1; }
static int my_RSA_sign(int t, const unsigned char *m, unsigned int ml, unsigned char *s, unsigned int *sl, RSA *r) {
    if (sl) *sl = 0;
    return 0;
}
static int my_EVP_PKEY_verify(EVP_PKEY_CTX *ctx, const unsigned char *s, size_t sl, const unsigned char *t, size_t tl) { return 1; }
static int my_X509_verify_cert(X509_STORE_CTX *ctx) { return 1; }
static int my_X509_check_private_key(X509 *x, EVP_PKEY *k) { return 1; }
static EVP_PKEY* my_PEM_read_bio_PrivateKey(BIO *bp, EVP_PKEY **x, pem_password_cb *cb, void *u) { return NULL; }
static int my_SSL_CTX_use_PrivateKey_file(SSL_CTX *ctx, const char *f, int t) { return 1; }
static int my_SSL_CTX_check_private_key(SSL_CTX *ctx) { return 1; }
static int my_SSL_CTX_load_verify_locations(SSL_CTX *ctx, const char *CAfile, const char *CApath) { return 1; }

// ObjC swizzling (used)
static IMP orig_UIDevice_identifierForVendor;
static id my_UIDevice_identifierForVendor(id self, SEL _cmd) {
    return [[NSUUID alloc] initWithUUIDString:@"00000000-0000-0000-0000-000000000000"];
}
static void my_LAContext_evaluatePolicy(id self, SEL _cmd, LAPolicy policy,
                                        NSString *localizedReason,
                                        void(^reply)(BOOL success, NSError *error)) {
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

// fishhook binding (uses all orig_* and my_* above)
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
    };
    rebind_symbols(bindings, sizeof(bindings)/sizeof(bindings[0]));
}

// __interpose (printf only)
typedef struct interpose_s { void *new_func; void *orig_func; } interpose_t;
#define INTERPOSE(new, orig) \
    __attribute__((used)) static const interpose_t interpose_##new \
    __attribute__((section("__DATA,__interpose"))) = { (void *)new, (void *)orig };

static int my_printf(const char *format, ...);
INTERPOSE(my_printf, printf)

static int my_printf(const char *format, ...) {
    if (strstr(format, "debug") || strstr(format, "jailbreak")) return 0;
    va_list args;
    va_start(args, format);
    int ret = vprintf(format, args);
    va_end(args);
    return ret;
}

// Security checks (no unused elements)
int is_simulator() {
#if TARGET_IPHONE_SIMULATOR
    return 1;
#else
    struct utsname info;
    uname(&info);
    return (strcmp(info.machine, "x86_64") == 0 || strcmp(info.machine, "i386") == 0);
#endif
}
int is_jailbroken_paths() {
    const char *paths[] = {
        "/Applications/Cydia.app", "/Library/MobileSubstrate/MobileSubstrate.dylib",
        "/bin/bash", "/usr/sbin/sshd", "/etc/apt", "/private/var/lib/apt/",
        "/private/var/stash", "/usr/libexec/cydia", "/usr/sbin/frida-server",
        "/usr/bin/ssh", "/var/checkra1n.dmg", "/.bootstrapped", NULL
    };
    for (int i=0; paths[i]; i++) if (access(paths[i], F_OK) == 0) return 1;
    return 0;
}
int is_cydia_installed() {
#if TARGET_OS_IPHONE
    Class ls = objc_getClass("LSApplicationWorkspace");
    if (ls) {
        SEL dw = sel_registerName("defaultWorkspace");
        SEL open = sel_registerName("openApplicationWithBundleID:");
        id ws = ((id(*)(id,SEL))objc_msgSend)((id)ls, dw);
        if (ws) return ((int(*)(id,SEL,id))objc_msgSend)(ws, open, @"com.saurik.Cydia");
    }
#endif
    return 0;
}
int is_dyld_hijacked() { return (getenv("DYLD_INSERT_LIBRARIES") || getenv("DYLD_FORCE_FLAT_NAMESPACE")) ? 1 : 0; }
int is_debugger_attached() {
    int name[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()};
    struct kinfo_proc info; size_t size = sizeof(info);
    info.kp_proc.p_flag = 0;
    if (sysctl(name,4,&info,&size,NULL,0) == -1) return 0;
    return (info.kp_proc.p_flag & P_TRACED) != 0;
}
int ptrace_deny_attach() { load_real_ptrace(); return (!real_ptrace || real_ptrace(PT_DENY_ATTACH,0,0,0) == -1) ? 1 : 0; }
int is_substrate_loaded() {
    for (uint32_t i=0; i<_dyld_image_count(); i++) {
        const char *name = _dyld_get_image_name(i);
        if (strstr(name,"MobileSubstrate")||strstr(name,"Substrate")||strstr(name,"CydiaSubstrate")) return 1;
    }
    return 0;
}
int is_ssh_running() { return (access("/usr/sbin/sshd", F_OK) == 0); }
int is_apt_installed() { return (access("/etc/apt", F_OK) == 0); }
int is_frida_installed() { return (access("/usr/sbin/frida-server", F_OK) == 0); }
int is_debugserver_installed() { return (access("/Developer/usr/bin/debugserver", F_OK) == 0); }

// Corrected check_provisioning
int check_provisioning() {
    FILE *fp = NULL;
    uint32_t size = 0;
    _NSGetExecutablePath(NULL, &size);
    char *execPath = (char *)malloc(size);
    if (!execPath) return 0;
    _NSGetExecutablePath(execPath, &size);
    char *lastSlash = strrchr(execPath, '/');
    if (lastSlash) {
        *lastSlash = '\0';
        char path[MAXPATHLEN];
        snprintf(path, sizeof(path), "%s/embedded.mobileprovision", execPath);
        fp = fopen(path, "r");
    }
    free(execPath);
    if (!fp) return 0;
    fseek(fp, 0, SEEK_END);
    long len = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    char *data = (char *)malloc(len + 1);
    if (!data) {
        fclose(fp);
        return 0;
    }
    fread(data, 1, len, fp);
    fclose(fp);
    data[len] = '\0';
    int is_debuggable = (strstr(data, "<key>get-task-allow</key><true/>") != NULL);
    free(data);
    return is_debuggable;
}

int check_env() {
    const char *vars[]={"DYLD_PRINT_TO_FILE","DYLD_INSERT_LIBRARIES","CFNETWORK_DIAGNOSTICS","OBJC_DISABLE_VALIDATION",NULL};
    for (int i=0; vars[i]; i++) if (getenv(vars[i])) return 1;
    return 0;
}
int check_ppid() {
    pid_t ppid=getppid(); char path[256]; snprintf(path,sizeof(path),"/proc/%d/exe",ppid);
    if (access(path,F_OK)==0) {
        char target[256]; ssize_t len=readlink(path,target,sizeof(target)-1);
        if (len!=-1) { target[len]='\0'; if (strstr(target,"debugserver")||strstr(target,"lldb")) return 1; }
    }
    return 0;
}
int is_frida_loaded() { return (dlopen("frida-agent.dylib", RTLD_NOLOAD) != NULL); }
void perform_security_checks() {
    int t=0;
    if (is_simulator()) t+=10;
    if (is_jailbroken_paths()) t+=20;
    if (is_cydia_installed()) t+=10;
    if (is_dyld_hijacked()) t+=30;
    if (is_debugger_attached()) t+=50;
    if (ptrace_deny_attach()) t+=30;
    if (is_substrate_loaded()) t+=20;
    if (is_ssh_running()) t+=10;
    if (is_apt_installed()) t+=10;
    if (is_frida_installed() || is_frida_loaded()) t+=40;
    if (is_debugserver_installed()) t+=20;
    if (check_provisioning()) t+=30;
    if (check_env()) t+=10;
    if (check_ppid()) t+=40;
    if (t>50) { usleep(rand()%100000); _exit(1); }
}

// Constructor
__attribute__((constructor))
void init_hook() {
    srand((unsigned int)time(NULL));
    load_real_ptrace();
    perform_security_checks();
    fishhook_bindings();
    swizzle_objc_methods();
}
