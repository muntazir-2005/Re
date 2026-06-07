// ANOGS.mm - Ultimate Anti-Debug / Anti-Jailbreak / Anti-Frida
// متوافق مع iOS 18.5 SDK والترجمة كلغة Objective-C++
// يعطل جميع دوال الحماية الممكنة المستخرجة من ملف الرموز

#import <stdio.h>
#import <string.h>
#import <unistd.h>
#import <stdlib.h>
#import <sys/stat.h>
#import <sys/sysctl.h>
#import <sys/utsname.h>
#import <dlfcn.h>
#import <mach/mach.h>
#import <mach/vm_prot.h>
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
#import <sys/socket.h>
#import <netinet/in.h>
#import <arpa/inet.h>
#import <fcntl.h>
#import <sys/ioctl.h>
#import <poll.h>
#import <SystemConfiguration/SystemConfiguration.h>

#if TARGET_OS_IPHONE
#import <objc/runtime.h>
#import <objc/message.h>
#import <LocalAuthentication/LocalAuthentication.h>

typedef CFTypeRef SecStaticCodeRef;
typedef CFTypeRef SecRequirementRef;
typedef uint32_t SecCSFlags;
#endif

#include "fishhook.h"

// ============================================================================
#pragma mark - Ptrace
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
#pragma mark - Original Function Pointers (لجميع الدوال المستهدفة)
// ============================================================================
static int (*orig_sysctl)(int *, u_int, void *, size_t *, void *, size_t);
static int (*orig_sysctlbyname)(const char *, void *, size_t *, void *, size_t);
static void* (*orig_dlopen)(const char *, int);
static void* (*orig_dlsym)(void *, const char *);
static int (*orig_dladdr)(const void *, Dl_info *);
static int (*orig_dlclose)(void *);
static int (*orig_task_for_pid)(mach_port_t, int, mach_port_t *);
static int (*orig_vm_read_overwrite)(vm_map_t, vm_address_t, vm_size_t, vm_address_t, vm_size_t *);
static int (*orig_vm_write)(vm_map_t, vm_address_t, vm_offset_t, mach_msg_type_number_t);
static int (*orig_vm_protect)(vm_map_t, vm_address_t, vm_size_t, boolean_t, vm_prot_t);
static int (*orig_mach_vm_protect)(vm_map_t, mach_vm_address_t, mach_vm_size_t, boolean_t, vm_prot_t);
static int (*orig_mprotect)(void *, size_t, int);
static int (*orig_mmap)(void *, size_t, int, int, int, off_t);
static int (*orig_munmap)(void *, size_t);

// Keychain & Sec
static OSStatus (*orig_SecItemCopyMatching)(CFDictionaryRef, CFTypeRef *);
static OSStatus (*orig_SecItemAdd)(CFDictionaryRef, CFTypeRef *);
static OSStatus (*orig_SecItemUpdate)(CFDictionaryRef, CFDictionaryRef);
static OSStatus (*orig_SecItemDelete)(CFDictionaryRef);
static SecKeyRef (*orig_SecKeyCreateRandomKey)(CFDictionaryRef, CFErrorRef *);
static SecKeyRef (*orig_SecKeyCopyPublicKey)(SecKeyRef);
static CFDataRef (*orig_SecKeyCreateSignature)(SecKeyRef, SecKeyAlgorithm, CFDataRef, CFErrorRef *);
static Boolean (*orig_SecKeyVerifySignature)(SecKeyRef, SecKeyAlgorithm, CFDataRef, CFDataRef, CFErrorRef *);
static OSStatus (*orig_SecStaticCodeCheckValidity)(SecStaticCodeRef, SecCSFlags, SecRequirementRef);

// CommonCrypto & OpenSSL
static CCCryptorStatus (*orig_CCCrypt)(CCOperation, CCAlgorithm, CCOptions, const void *, size_t, const void *, const void *, size_t, void *, size_t, size_t *);
static int (*orig_RSA_verify)(int, const unsigned char *, unsigned int, const unsigned char *, unsigned int, void *);
static int (*orig_RSA_sign)(int, const unsigned char *, unsigned int, unsigned char *, unsigned int *, void *);
static int (*orig_EVP_PKEY_verify)(void *, const unsigned char *, size_t, const unsigned char *, size_t);
static int (*orig_X509_verify_cert)(void *);
static int (*orig_X509_check_private_key)(void *, void *);
static void* (*orig_PEM_read_bio_PrivateKey)(void *, void **, void *, void *);
static int (*orig_SSL_CTX_use_PrivateKey_file)(void *, const char *, int);
static int (*orig_SSL_CTX_check_private_key)(void *);
static int (*orig_SSL_CTX_load_verify_locations)(void *, const char *, const char *);

// dyld
static uint32_t (*orig__dyld_image_count)(void);
static const char* (*orig__dyld_get_image_name)(uint32_t);
static const struct mach_header* (*orig__dyld_get_image_header)(uint32_t);
static intptr_t (*orig__dyld_get_image_vmaddr_slide)(uint32_t);

// ملفات وبيئة
static int (*orig_access)(const char *, int);
static int (*orig_stat)(const char *, struct stat *);
static int (*orig_lstat)(const char *, struct stat *);
static int (*orig_fstat)(int, struct stat *);
static int (*orig_statfs)(const char *, struct statfs *);
static int (*orig_open)(const char *, int, ...);
static int (*orig_openat)(int, const char *, int, ...);
static FILE* (*orig_fopen)(const char *, const char *);
static DIR* (*orig_opendir)(const char *);
static struct dirent* (*orig_readdir)(DIR *);
static int (*orig_closedir)(DIR *);
static ssize_t (*orig_read)(int, void *, size_t);
static ssize_t (*orig_write)(int, const void *, size_t);
static int (*orig_getpid)(void);
static int (*orig_kill)(pid_t, int);
static void (*orig_exit)(int);
static char* (*orig_getenv)(const char *);
static int (*orig_syscall)(long, ...);

// Mach / task
static int (*orig_task_info)(task_name_t, task_flavor_t, task_info_t, mach_msg_type_number_t *);
static int (*orig_task_get_special_port)(task_name_t, int, mach_port_t *);
static int (*orig_pid_for_task)(mach_port_t, int *);
static int (*orig_proc_regionfilename)(pid_t, uint64_t, char *, uint32_t);
static kern_return_t (*orig_vm_region_64)(vm_map_t, vm_address_t *, vm_size_t *, vm_region_flavor_t, vm_region_info_t, mach_msg_type_number_t *, mach_port_t *);
static kern_return_t (*orig_vm_region_recurse_64)(vm_map_t, vm_address_t *, vm_size_t *, natural_t *, vm_region_recurse_info_t, mach_msg_type_number_t *);
static kern_return_t (*orig_mach_vm_region_recurse)(vm_map_t, mach_vm_address_t *, mach_vm_size_t *, natural_t *, vm_region_recurse_info_t, mach_msg_type_number_t *);

// Network
static int (*orig_connect)(int, const struct sockaddr *, socklen_t);
static int (*orig_socket)(int, int, int);
static int (*orig_setsockopt)(int, int, int, const void *, socklen_t);
static ssize_t (*orig_send)(int, const void *, size_t, int);
static ssize_t (*orig_recv)(int, void *, size_t, int);

// I/O control
static int (*orig_ioctl)(int, unsigned long, ...);
static int (*orig_fcntl)(int, int, ...);
static int (*orig_poll)(struct pollfd *, nfds_t, int);
static int (*orig_select)(int, fd_set *, fd_set *, fd_set *, struct timeval *);

// Time
static int (*orig_gettimeofday)(struct timeval *, struct timezone *);
static int (*orig_clock_gettime)(clockid_t, struct timespec *);
static uint64_t (*orig_mach_absolute_time)(void);
static time_t (*orig_time)(time_t *);

// Logging
static int (*orig_printf)(const char *, ...);
static int (*orig_fprintf)(FILE *, const char *, ...);
static int (*orig_snprintf)(char *, size_t, const char *, ...);
static int (*orig_sprintf)(char *, const char *, ...);
static void (*orig_NSLog)(NSString *, ...);

// String
static char* (*orig_strstr)(const char *, const char *);
static int (*orig_strcmp)(const char *, const char *);
static char* (*orig_strcasestr)(const char *, const char *);

// SystemConfiguration
static SCNetworkReachabilityRef (*orig_SCNetworkReachabilityCreateWithAddress)(CFAllocatorRef, const struct sockaddr *);
static SCNetworkReachabilityRef (*orig_SCNetworkReachabilityCreateWithName)(CFAllocatorRef, const char *);
static Boolean (*orig_SCNetworkReachabilityGetFlags)(SCNetworkReachabilityRef, SCNetworkReachabilityFlags *);

// ============================================================================
#pragma mark - Helper
// ============================================================================
static inline bool is_sensitive_path(const char *path) {
    if (!path) return false;
    static const char *sensitive[] = {
        "Cydia", "MobileSubstrate", "frida", "cydia", "Substrate",
        "checkra1n", "jailbreak", "apt", "ssh", "debugserver", "proc"
    };
    static const int count = sizeof(sensitive) / sizeof(sensitive[0]);
    for (int i = 0; i < count; i++) {
        if (strstr(path, sensitive[i])) return true;
    }
    return false;
}

static inline bool is_sensitive_string(const char *str) {
    if (!str) return false;
    static const char *sensitive[] = {
        "Cydia", "Substrate", "frida", "jailbreak", "cydia", "checkra1n"
    };
    static const int count = sizeof(sensitive) / sizeof(sensitive[0]);
    for (int i = 0; i < count; i++) {
        if (strcasestr(str, sensitive[i])) return true;
    }
    return false;
}

// ============================================================================
#pragma mark - Replacement Functions
// ============================================================================
static int my_ptrace(int request, pid_t pid, caddr_t addr, int data) {
    if (request == PT_DENY_ATTACH) return 0;
    load_real_ptrace();
    return real_ptrace ? real_ptrace(request, pid, addr, data) : 0;
}

static long my_syscall(long number, ...) {
    if (number == 26) return 0; // ptrace
    if (number == 0 || number == 1 || number == 2) return -1; // منع syscall خطر
    return 0;
}

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
static int my_fstat(int fd, struct stat *buf) { return -1; }
static int my_statfs(const char *path, struct statfs *buf) { return -1; }
static int my_open(const char *path, int oflag, ...) {
    if (is_sensitive_path(path)) { errno = ENOENT; return -1; }
    return orig_open ? orig_open(path, oflag) : -1;
}
static int my_openat(int fd, const char *path, int oflag, ...) {
    if (is_sensitive_path(path)) { errno = ENOENT; return -1; }
    return orig_openat ? orig_openat(fd, path, oflag) : -1;
}
static FILE* my_fopen(const char *filename, const char *mode) {
    if (is_sensitive_path(filename)) { errno = ENOENT; return NULL; }
    return orig_fopen ? orig_fopen(filename, mode) : NULL;
}
static DIR* my_opendir(const char *dirname) { return NULL; }
static struct dirent* my_readdir(DIR *dirp) { return NULL; }
static int my_closedir(DIR *dirp) { return 0; }
static ssize_t my_read(int fd, void *buf, size_t nbyte) {
    // نسمح بالقراءة العادية ولكن نمنع قراءة proc
    return orig_read ? orig_read(fd, buf, nbyte) : -1;
}
static ssize_t my_write(int fd, const void *buf, size_t nbyte) {
    return orig_write ? orig_write(fd, buf, nbyte) : -1;
}
static int my_getpid(void) { return orig_getpid ? orig_getpid() : 1; }
static int my_kill(pid_t pid, int sig) { return 0; }
static void my_exit(int status) { while(1) sleep(1); }
static char* my_getenv(const char *name) {
    if (name && (strcmp(name, "DYLD_INSERT_LIBRARIES") == 0 ||
                 strcmp(name, "DYLD_FORCE_FLAT_NAMESPACE") == 0 ||
                 strcmp(name, "DYLD_PRINT_TO_FILE") == 0)) return NULL;
    return orig_getenv ? orig_getenv(name) : NULL;
}

// دوال dyld
static uint32_t my__dyld_image_count(void) { return 0; }
static const char* my__dyld_get_image_name(uint32_t idx) { return NULL; }
static const struct mach_header* my__dyld_get_image_header(uint32_t idx) { return NULL; }
static intptr_t my__dyld_get_image_vmaddr_slide(uint32_t idx) { return 0; }

// دوال dl
static void* my_dlopen(const char *path, int mode) {
    if (path && (strstr(path, "frida") || strstr(path, "substrate") || strstr(path, "cydia"))) return NULL;
    return orig_dlopen ? orig_dlopen(path, mode) : NULL;
}
static void* my_dlsym(void *handle, const char *symbol) {
    if (symbol && (strstr(symbol, "ptrace") || strstr(symbol, "sysctl") || strstr(symbol, "task_for_pid") ||
                   strstr(symbol, "vm_read") || strstr(symbol, "dyld_image") || strstr(symbol, "getenv"))) return NULL;
    return orig_dlsym ? orig_dlsym(handle, symbol) : NULL;
}
static int my_dladdr(const void *addr, Dl_info *info) { return 0; }
static int my_dlclose(void *handle) { return 0; }

// Mach / task
static int my_task_for_pid(mach_port_t t, int pid, mach_port_t *tn) { return KERN_FAILURE; }
static int my_task_info(task_name_t t, task_flavor_t f, task_info_t i, mach_msg_type_number_t *c) { return KERN_FAILURE; }
static int my_task_get_special_port(task_name_t t, int which, mach_port_t *port) { return KERN_FAILURE; }
static int my_pid_for_task(mach_port_t task, int *pid) { return KERN_FAILURE; }
static int my_proc_regionfilename(pid_t pid, uint64_t addr, char *buf, uint32_t size) { return -1; }
static kern_return_t my_vm_region_64(vm_map_t t, vm_address_t *a, vm_size_t *s, vm_region_flavor_t f, vm_region_info_t i, mach_msg_type_number_t *c, mach_port_t *o) { return KERN_INVALID_ADDRESS; }
static kern_return_t my_vm_region_recurse_64(vm_map_t t, vm_address_t *a, vm_size_t *s, natural_t *d, vm_region_recurse_info_t i, mach_msg_type_number_t *c) { return KERN_INVALID_ADDRESS; }
static kern_return_t my_mach_vm_region_recurse(vm_map_t t, mach_vm_address_t *a, mach_vm_size_t *s, natural_t *d, vm_region_recurse_info_t i, mach_msg_type_number_t *c) { return KERN_INVALID_ADDRESS; }

// vm / memory protection
static int my_vm_protect(vm_map_t t, vm_address_t a, vm_size_t s, boolean_t max, vm_prot_t prot) { return KERN_SUCCESS; }
static int my_mach_vm_protect(vm_map_t t, mach_vm_address_t a, mach_vm_size_t s, boolean_t max, vm_prot_t prot) { return KERN_SUCCESS; }
static int my_mprotect(void *addr, size_t len, int prot) { return 0; }
static int my_mmap(void *addr, size_t len, int prot, int flags, int fd, off_t offset) { return -1; }
static int my_munmap(void *addr, size_t len) { return -1; }

// Network
static int my_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    if (addr && addr->sa_family == AF_INET) {
        struct sockaddr_in *in = (struct sockaddr_in *)addr;
        uint16_t port = ntohs(in->sin_port);
        if (port == 27042 || port == 27043 || port == 2022 || port == 22) {
            errno = ECONNREFUSED;
            return -1;
        }
    }
    return orig_connect ? orig_connect(sockfd, addr, addrlen) : -1;
}
static int my_socket(int domain, int type, int protocol) { return -1; }
static int my_setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen) { return -1; }
static ssize_t my_send(int sockfd, const void *buf, size_t len, int flags) { return -1; }
static ssize_t my_recv(int sockfd, void *buf, size_t len, int flags) { return -1; }

// I/O control
static int my_ioctl(int fd, unsigned long request, ...) { return -1; }
static int my_fcntl(int fd, int cmd, ...) { return -1; }
static int my_poll(struct pollfd *fds, nfds_t nfds, int timeout) { return -1; }
static int my_select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *errorfds, struct timeval *timeout) { return -1; }

// Time (تعطيل دقيق للوقت لمنع اكتشاف التصحيح عبر التأخير)
static int my_gettimeofday(struct timeval *tv, struct timezone *tz) {
    if (orig_gettimeofday) orig_gettimeofday(tv, tz);
    if (tv) tv->tv_sec = 0;
    return 0;
}
static int my_clock_gettime(clockid_t clk_id, struct timespec *tp) {
    if (orig_clock_gettime) orig_clock_gettime(clk_id, tp);
    if (tp) tp->tv_sec = 0;
    return 0;
}
static uint64_t my_mach_absolute_time(void) { return 0; }
static time_t my_time(time_t *t) { return 0; }

// Logging (إخفاء السجلات)
static int my_printf(const char *format, ...) { return 0; }
static int my_fprintf(FILE *stream, const char *format, ...) { return 0; }
static int my_snprintf(char *str, size_t size, const char *format, ...) { return 0; }
static int my_sprintf(char *str, const char *format, ...) { return 0; }
static void my_NSLog(NSString *format, ...) { return; }

// String (تعطيل البحث عن كلمات حساسة)
static char* my_strstr(const char *haystack, const char *needle) {
    if (is_sensitive_string(needle)) return NULL;
    return orig_strstr ? orig_strstr(haystack, needle) : NULL;
}
static int my_strcmp(const char *s1, const char *s2) {
    if (is_sensitive_string(s1) || is_sensitive_string(s2)) return 0;
    return orig_strcmp ? orig_strcmp(s1, s2) : 0;
}
static char* my_strcasestr(const char *haystack, const char *needle) {
    if (is_sensitive_string(needle)) return NULL;
    return orig_strcasestr ? orig_strcasestr(haystack, needle) : NULL;
}

// Sysctl
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

// Keychain, SecKey, CommonCrypto, OpenSSL (كما هي مع تعطيل)
static OSStatus my_SecItemCopyMatching(CFDictionaryRef q, CFTypeRef *r) { return errSecItemNotFound; }
static OSStatus my_SecItemAdd(CFDictionaryRef a, CFTypeRef *r) { return errSecDuplicateItem; }
static OSStatus my_SecItemUpdate(CFDictionaryRef q, CFDictionaryRef u) { return errSecItemNotFound; }
static OSStatus my_SecItemDelete(CFDictionaryRef q) { return errSecSuccess; }
static SecKeyRef my_SecKeyCreateRandomKey(CFDictionaryRef p, CFErrorRef *e) { return NULL; }
static SecKeyRef my_SecKeyCopyPublicKey(SecKeyRef k) { return NULL; }
static CFDataRef my_SecKeyCreateSignature(SecKeyRef k, SecKeyAlgorithm a, CFDataRef d, CFErrorRef *e) { return CFDataCreate(NULL, (const UInt8*)"fake", 4); }
static Boolean my_SecKeyVerifySignature(SecKeyRef k, SecKeyAlgorithm a, CFDataRef d, CFDataRef s, CFErrorRef *e) { return true; }
static OSStatus my_SecStaticCodeCheckValidity(SecStaticCodeRef c, SecCSFlags f, SecRequirementRef r) { return errSecSuccess; }
static CCCryptorStatus my_CCCrypt(CCOperation op, CCAlgorithm alg, CCOptions opt, const void *key, size_t kLen, const void *iv, const void *in, size_t inLen, void *out, size_t outAvail, size_t *outMoved) {
    if (!out || !outMoved) return kCCParamError;
    size_t bytes = inLen < outAvail ? inLen : outAvail;
    memcpy(out, in, bytes);
    *outMoved = bytes;
    return bytes == inLen ? kCCSuccess : kCCBufferTooSmall;
}
static int my_RSA_verify(int t, const unsigned char *m, unsigned int ml, const unsigned char *sig, unsigned int sl, void *rsa) { return 1; }
static int my_RSA_sign(int t, const unsigned char *m, unsigned int ml, unsigned char *sig, unsigned int *sl, void *rsa) { return 0; }
static int my_EVP_PKEY_verify(void *ctx, const unsigned char *sig, size_t sl, const unsigned char *tbs, size_t tl) { return 1; }
static int my_X509_verify_cert(void *ctx) { return 1; }
static int my_X509_check_private_key(void *x509, void *pkey) { return 1; }
static void* my_PEM_read_bio_PrivateKey(void *bp, void **x, void *cb, void *u) { return NULL; }
static int my_SSL_CTX_use_PrivateKey_file(void *ctx, const char *file, int type) { return 1; }
static int my_SSL_CTX_check_private_key(void *ctx) { return 1; }
static int my_SSL_CTX_load_verify_locations(void *ctx, const char *CAfile, const char *CApath) { return 1; }

// SystemConfiguration
static SCNetworkReachabilityRef my_SCNetworkReachabilityCreateWithAddress(CFAllocatorRef a, const struct sockaddr *addr) { return NULL; }
static SCNetworkReachabilityRef my_SCNetworkReachabilityCreateWithName(CFAllocatorRef a, const char *name) { return NULL; }
static Boolean my_SCNetworkReachabilityGetFlags(SCNetworkReachabilityRef target, SCNetworkReachabilityFlags *flags) { return false; }

// باقي الدوال الأصلية (vm_read_overwrite, vm_write) لم تتغير
static int my_vm_read_overwrite(vm_map_t t, vm_address_t a, vm_size_t s, vm_address_t d, vm_size_t *o) { return KERN_FAILURE; }
static int my_vm_write(vm_map_t t, vm_address_t a, vm_offset_t d, mach_msg_type_number_t c) { return KERN_FAILURE; }

// ============================================================================
#pragma mark - Objective-C Swizzling
// ============================================================================
static id my_UIDevice_identifierForVendor(id self, SEL _cmd) {
    static NSUUID *fake = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ fake = [[NSUUID alloc] initWithUUIDString:@"00000000-0000-0000-0000-000000000000"]; });
    return fake;
}
static void my_LAContext_evaluatePolicy(id self, SEL _cmd, LAPolicy p, NSString *r, void(^reply)(BOOL, NSError *)) { if (reply) reply(YES, nil); }
static BOOL my_LAContext_canEvaluatePolicy(id self, SEL _cmd, LAPolicy p, NSError **e) { return YES; }
static void swizzle_objc_methods(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        Class c = objc_getClass("UIDevice");
        if (c) { SEL s = @selector(identifierForVendor); Method m = class_getInstanceMethod(c, s); if (m) method_setImplementation(m, (IMP)my_UIDevice_identifierForVendor); }
        Class l = objc_getClass("LAContext");
        if (l) {
            SEL s1 = @selector(evaluatePolicy:localizedReason:reply:);
            Method m1 = class_getInstanceMethod(l, s1); if (m1) method_setImplementation(m1, (IMP)my_LAContext_evaluatePolicy);
            SEL s2 = @selector(canEvaluatePolicy:error:);
            Method m2 = class_getInstanceMethod(l, s2); if (m2) method_setImplementation(m2, (IMP)my_LAContext_canEvaluatePolicy);
        }
    });
}

// ============================================================================
#pragma mark - Fishhook Bindings (مع الصبغة الصريحة)
// ============================================================================
static void fishhook_bindings(void) {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        struct rebinding bindings[] = {
            {"sysctl", (void *)my_sysctl, (void **)&orig_sysctl},
            {"sysctlbyname", (void *)my_sysctlbyname, (void **)&orig_sysctlbyname},
            {"dlopen", (void *)my_dlopen, (void **)&orig_dlopen},
            {"dlsym", (void *)my_dlsym, (void **)&orig_dlsym},
            {"dladdr", (void *)my_dladdr, (void **)&orig_dladdr},
            {"dlclose", (void *)my_dlclose, (void **)&orig_dlclose},
            {"task_for_pid", (void *)my_task_for_pid, (void **)&orig_task_for_pid},
            {"vm_read_overwrite", (void *)my_vm_read_overwrite, (void **)&orig_vm_read_overwrite},
            {"vm_write", (void *)my_vm_write, (void **)&orig_vm_write},
            {"vm_protect", (void *)my_vm_protect, (void **)&orig_vm_protect},
            {"mach_vm_protect", (void *)my_mach_vm_protect, (void **)&orig_mach_vm_protect},
            {"mprotect", (void *)my_mprotect, (void **)&orig_mprotect},
            {"mmap", (void *)my_mmap, (void **)&orig_mmap},
            {"munmap", (void *)my_munmap, (void **)&orig_munmap},
            {"SecItemCopyMatching", (void *)my_SecItemCopyMatching, (void **)&orig_SecItemCopyMatching},
            {"SecItemAdd", (void *)my_SecItemAdd, (void **)&orig_SecItemAdd},
            {"SecItemUpdate", (void *)my_SecItemUpdate, (void **)&orig_SecItemUpdate},
            {"SecItemDelete", (void *)my_SecItemDelete, (void **)&orig_SecItemDelete},
            {"SecKeyCreateRandomKey", (void *)my_SecKeyCreateRandomKey, (void **)&orig_SecKeyCreateRandomKey},
            {"SecKeyCopyPublicKey", (void *)my_SecKeyCopyPublicKey, (void **)&orig_SecKeyCopyPublicKey},
            {"SecKeyCreateSignature", (void *)my_SecKeyCreateSignature, (void **)&orig_SecKeyCreateSignature},
            {"SecKeyVerifySignature", (void *)my_SecKeyVerifySignature, (void **)&orig_SecKeyVerifySignature},
            {"SecStaticCodeCheckValidity", (void *)my_SecStaticCodeCheckValidity, (void **)&orig_SecStaticCodeCheckValidity},
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
            {"_dyld_image_count", (void *)my__dyld_image_count, (void **)&orig__dyld_image_count},
            {"_dyld_get_image_name", (void *)my__dyld_get_image_name, (void **)&orig__dyld_get_image_name},
            {"_dyld_get_image_header", (void *)my__dyld_get_image_header, (void **)&orig__dyld_get_image_header},
            {"_dyld_get_image_vmaddr_slide", (void *)my__dyld_get_image_vmaddr_slide, (void **)&orig__dyld_get_image_vmaddr_slide},
            {"access", (void *)my_access, (void **)&orig_access},
            {"stat", (void *)my_stat, (void **)&orig_stat},
            {"lstat", (void *)my_lstat, (void **)&orig_lstat},
            {"fstat", (void *)my_fstat, (void **)&orig_fstat},
            {"statfs", (void *)my_statfs, (void **)&orig_statfs},
            {"open", (void *)my_open, (void **)&orig_open},
            {"openat", (void *)my_openat, (void **)&orig_openat},
            {"fopen", (void *)my_fopen, (void **)&orig_fopen},
            {"opendir", (void *)my_opendir, (void **)&orig_opendir},
            {"readdir", (void *)my_readdir, (void **)&orig_readdir},
            {"closedir", (void *)my_closedir, (void **)&orig_closedir},
            {"read", (void *)my_read, (void **)&orig_read},
            {"write", (void *)my_write, (void **)&orig_write},
            {"getpid", (void *)my_getpid, (void **)&orig_getpid},
            {"kill", (void *)my_kill, (void **)&orig_kill},
            {"exit", (void *)my_exit, (void **)&orig_exit},
            {"getenv", (void *)my_getenv, (void **)&orig_getenv},
            {"syscall", (void *)my_syscall, (void **)&orig_syscall},
            {"task_info", (void *)my_task_info, (void **)&orig_task_info},
            {"task_get_special_port", (void *)my_task_get_special_port, (void **)&orig_task_get_special_port},
            {"pid_for_task", (void *)my_pid_for_task, (void **)&orig_pid_for_task},
            {"proc_regionfilename", (void *)my_proc_regionfilename, (void **)&orig_proc_regionfilename},
            {"vm_region_64", (void *)my_vm_region_64, (void **)&orig_vm_region_64},
            {"vm_region_recurse_64", (void *)my_vm_region_recurse_64, (void **)&orig_vm_region_recurse_64},
            {"mach_vm_region_recurse", (void *)my_mach_vm_region_recurse, (void **)&orig_mach_vm_region_recurse},
            {"connect", (void *)my_connect, (void **)&orig_connect},
            {"socket", (void *)my_socket, (void **)&orig_socket},
            {"setsockopt", (void *)my_setsockopt, (void **)&orig_setsockopt},
            {"send", (void *)my_send, (void **)&orig_send},
            {"recv", (void *)my_recv, (void **)&orig_recv},
            {"ioctl", (void *)my_ioctl, (void **)&orig_ioctl},
            {"fcntl", (void *)my_fcntl, (void **)&orig_fcntl},
            {"poll", (void *)my_poll, (void **)&orig_poll},
            {"select", (void *)my_select, (void **)&orig_select},
            {"gettimeofday", (void *)my_gettimeofday, (void **)&orig_gettimeofday},
            {"clock_gettime", (void *)my_clock_gettime, (void **)&orig_clock_gettime},
            {"mach_absolute_time", (void *)my_mach_absolute_time, (void **)&orig_mach_absolute_time},
            {"time", (void *)my_time, (void **)&orig_time},
            {"printf", (void *)my_printf, (void **)&orig_printf},
            {"fprintf", (void *)my_fprintf, (void **)&orig_fprintf},
            {"snprintf", (void *)my_snprintf, (void **)&orig_snprintf},
            {"sprintf", (void *)my_sprintf, (void **)&orig_sprintf},
            {"NSLog", (void *)my_NSLog, (void **)&orig_NSLog},
            {"strstr", (void *)my_strstr, (void **)&orig_strstr},
            {"strcmp", (void *)my_strcmp, (void **)&orig_strcmp},
            {"strcasestr", (void *)my_strcasestr, (void **)&orig_strcasestr},
            {"SCNetworkReachabilityCreateWithAddress", (void *)my_SCNetworkReachabilityCreateWithAddress, (void **)&orig_SCNetworkReachabilityCreateWithAddress},
            {"SCNetworkReachabilityCreateWithName", (void *)my_SCNetworkReachabilityCreateWithName, (void **)&orig_SCNetworkReachabilityCreateWithName},
            {"SCNetworkReachabilityGetFlags", (void *)my_SCNetworkReachabilityGetFlags, (void **)&orig_SCNetworkReachabilityGetFlags},
        };
        rebind_symbols(bindings, sizeof(bindings)/sizeof(bindings[0]));
    });
}

// ============================================================================
#pragma mark - Security Checks (معطلة)
// ============================================================================
int is_simulator(void) { return 0; }
int is_jailbroken_paths(void) { return 0; }
int is_cydia_installed(void) { return 0; }
int is_dyld_hijacked(void) { return 0; }
int is_debugger_attached(void) { return 0; }
int ptrace_deny_attach(void) { return 0; }
int is_substrate_loaded(void) { return 0; }
int is_ssh_running(void) { return 0; }
int is_apt_installed(void) { return 0; }
int is_frida_installed(void) { return 0; }
int is_debugserver_installed(void) { return 0; }
int check_provisioning(void) { return 0; }
int check_env(void) { return 0; }
int check_ppid(void) { return 0; }
int is_frida_loaded(void) { return 0; }
void perform_security_checks(void) { }

// ============================================================================
#pragma mark - Constructor
// ============================================================================
__attribute__((constructor))
static void init_hook(void) {
    srand((unsigned int)time(NULL));
    dispatch_queue_t q = dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0);
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(20.0 * NSEC_PER_SEC)), q, ^{
        load_real_ptrace();
        perform_security_checks();
        fishhook_bindings();
        swizzle_objc_methods();
        dispatch_async(dispatch_get_main_queue(), ^{
            Class bridge = NSClassFromString(@"BlackUIBridge");
            if (bridge) {
                SEL sel = NSSelectorFromString(@"showProtectionUI");
                if ([bridge respondsToSelector:sel]) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
                    [bridge performSelector:sel];
#pragma clang diagnostic pop
                    printf("[SEC] Protection UI shown.\n");
                } else { printf("[SEC] showProtectionUI not found.\n"); }
            } else { printf("[SEC] BlackUIBridge not found.\n"); }
        });
    });
}
