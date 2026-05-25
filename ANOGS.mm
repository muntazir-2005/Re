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
#import <dispatch/dispatch.h>
#import <sys/syscall.h>
#import <netinet/in.h>
#import <SystemConfiguration/SystemConfiguration.h>
#import <mach/mach_time.h>
#import <netdb.h>

#if TARGET_OS_IPHONE
#import <objc/runtime.h>
#import <objc/message.h>
#import <LocalAuthentication/LocalAuthentication.h>
#import <UIKit/UIKit.h>
#endif

#include "fishhook.h"

// ptrace
#define PT_DENY_ATTACH 31
typedef int (*ptrace_ptr_t)(int, pid_t, caddr_t, int);
static ptrace_ptr_t real_ptrace = NULL;
static void load_real_ptrace(void) {
    if (!real_ptrace) {
        real_ptrace = (ptrace_ptr_t)dlsym(RTLD_DEFAULT, "ptrace");
    }
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

// New additional function pointers
static int (*orig_proc_regionfilename)(int pid, uint64_t address, char *buffer, uint32_t bufferSize);
static int (*orig_task_info)(task_name_t target_task, task_flavor_t flavor, task_info_t task_info_out, mach_msg_type_number_t *task_info_count);
static int (*orig_pid_for_task)(mach_port_t task, int *pid);
static pid_t (*orig_getpid)(void);
static uid_t (*orig_getuid)(void);
static int (*orig_stat)(const char *path, struct stat *buf);
static int (*orig_access)(const char *path, int mode);
static int (*orig_kill)(pid_t pid, int sig);
static long (*orig_syscall)(long number, ...);
static int (*orig_ioctl)(int fildes, unsigned long request, ...);
static uint32_t (*orig_dyld_image_count)(void);
static const char* (*orig_dyld_get_image_name)(uint32_t image_index);
static const struct mach_header* (*orig_dyld_get_image_header)(uint32_t image_index);
static intptr_t (*orig_dyld_get_image_vmaddr_slide)(uint32_t image_index);
static int (*orig_dladdr)(const void *addr, Dl_info *info);
static void* (*orig_mmap)(void *addr, size_t len, int prot, int flags, int fd, off_t offset);
static int (*orig_mprotect)(void *addr, size_t len, int prot);
static int (*orig_munmap)(void *addr, size_t len);
static int (*orig_vm_read)(vm_map_t target_task, vm_address_t address, vm_size_t size, vm_offset_t *data, mach_msg_type_number_t *dataCnt);
static int (*orig_vm_remap)(vm_map_t target_task, vm_address_t *address, vm_size_t size, vm_offset_t mask, int flags, vm_offset_t src_addr, boolean_t copy, vm_prot_t *protection, vm_prot_t *max_protection, vm_inherit_t inheritance);
static int (*orig_mach_vm_region_recurse)(vm_map_t target_task, mach_vm_address_t *address, mach_vm_size_t *size, natural_t *depth, vm_region_recurse_info_t info, mach_msg_type_number_t *infoCnt);
static int (*orig_mach_vm_remap)(vm_map_t target_task, mach_vm_address_t *address, mach_vm_size_t size, mach_vm_offset_t mask, int flags, vm_map_t src_task, mach_vm_address_t src_address, boolean_t copy, vm_prot_t *cur_protection, vm_prot_t *max_protection, vm_inherit_t inheritance);
static uint64_t (*orig_mach_absolute_time)(void);
static kern_return_t (*orig_mach_timebase_info)(mach_timebase_info_t info);
static mach_msg_return_t (*orig_mach_msg)(mach_msg_header_t *msg, mach_msg_option_t option, mach_msg_size_t send_size, mach_msg_size_t rcv_size, mach_port_name_t rcv_name, mach_msg_timeout_t timeout, mach_port_name_t notify);
static mach_port_t (*orig_mig_get_reply_port)(void);
static kern_return_t (*orig_vm_deallocate)(vm_map_t target_task, vm_address_t address, vm_size_t size);
static kern_return_t (*orig_vm_copy)(vm_map_t target_task, vm_address_t source_address, vm_size_t size, vm_address_t dest_address);
static SCNetworkReachabilityRef (*orig_SCNetworkReachabilityCreateWithAddress)(CFAllocatorRef allocator, const struct sockaddr *address);
static SCNetworkReachabilityRef (*orig_SCNetworkReachabilityCreateWithName)(CFAllocatorRef allocator, const char *name);
static Boolean (*orig_SCNetworkReachabilityGetFlags)(SCNetworkReachabilityRef target, SCNetworkReachabilityFlags *flags);
static Boolean (*orig_SCNetworkReachabilitySetCallback)(SCNetworkReachabilityRef target, SCNetworkReachabilityCallBack callout, SCNetworkReachabilityContext *context);
static Boolean (*orig_SCNetworkReachabilityScheduleWithRunLoop)(SCNetworkReachabilityRef target, CFRunLoopRef runLoop, CFStringRef runLoopMode);
static Boolean (*orig_SCNetworkReachabilityUnscheduleFromRunLoop)(SCNetworkReachabilityRef target, CFRunLoopRef runLoop, CFStringRef runLoopMode);
static CFDictionaryRef (*orig_CFNetworkCopySystemProxySettings)(void);
static int (*orig_connect)(int socket, const struct sockaddr *address, socklen_t address_len);
static int (*orig_socket)(int domain, int type, int protocol);
static int (*orig_setsockopt)(int socket, int level, int option_name, const void *option_value, socklen_t option_len);
static int (*orig_getaddrinfo)(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res);
static void (*orig_freeaddrinfo)(struct addrinfo *res);
static const char* (*orig_inet_ntop)(int af, const void *src, char *dst, socklen_t size);
static int (*orig_inet_pton)(int af, const char *src, void *dst);
static CFUUIDRef (*orig_CFUUIDCreate)(CFAllocatorRef allocator);
static CFStringRef (*orig_CFUUIDCreateString)(CFAllocatorRef allocator, CFUUIDRef uuid);
static void (*orig_CFRelease)(CFTypeRef cf);
static void (*orig_UIGraphicsBeginImageContextWithOptions)(CGSize size, BOOL opaque, CGFloat scale);
static UIImage* (*orig_UIGraphicsGetImageFromCurrentImageContext)(void);
static void (*orig_UIGraphicsEndImageContext)(void);
static int (*orig_pthread_create)(pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine)(void*), void *arg);
static pthread_t (*orig_pthread_self)(void);
static int (*orig_pthread_setname_np)(const char *name);
static int (*orig_pthread_getname_np)(pthread_t thread, char *name, size_t len);
static int (*orig_pthread_mutex_lock)(pthread_mutex_t *mutex);
static int (*orig_pthread_mutex_unlock)(pthread_mutex_t *mutex);
static int (*orig_pthread_mutex_trylock)(pthread_mutex_t *mutex);
static void (*orig_dispatch_once_f)(dispatch_once_t *predicate, void *context, dispatch_function_t function);
static dispatch_semaphore_t (*orig_dispatch_semaphore_create)(long value);
static long (*orig_dispatch_semaphore_wait)(dispatch_semaphore_t dsema, dispatch_time_t timeout);
static long (*orig_dispatch_semaphore_signal)(dispatch_semaphore_t dsema);
static void (*orig_dispatch_sync)(dispatch_queue_t queue, dispatch_block_t block);

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

static bool my_is_jb(void) { return false; }
static bool my_ROOTED(void) { return false; }
static bool my_DEBUGGER_ATTACHED(void) { return false; }
static bool my_isDebuggerAttached(void) { return false; }
static bool my_checkJailbreak(void) { return false; }
static bool my_hasCydia(void) { return false; }
static bool my_isJailbroken_c(void) { return false; }
static bool my_amIBeingDebugged(void) { return false; }

// New replacement functions
static int my_proc_regionfilename(int pid, uint64_t address, char *buffer, uint32_t bufferSize) { return -1; }
static int my_task_info(task_name_t target_task, task_flavor_t flavor, task_info_t task_info_out, mach_msg_type_number_t *task_info_count) {
    return orig_task_info ? orig_task_info(target_task, flavor, task_info_out, task_info_count) : KERN_FAILURE;
}
static int my_pid_for_task(mach_port_t task, int *pid) { return KERN_FAILURE; }
static pid_t my_getpid(void) { return orig_getpid ? orig_getpid() : 0; }
static uid_t my_getuid(void) { return 501; }
static int my_stat(const char *path, struct stat *buf) {
    if (path && (strstr(path, "/var/") || strstr(path, "/etc/apt") || strstr(path, "/usr/bin/ssh"))) return -1;
    return orig_stat ? orig_stat(path, buf) : -1;
}
static int my_access(const char *path, int mode) {
    if (path && (strstr(path, "/var/") || strstr(path, "Cydia") || strstr(path, "Substrate"))) return -1;
    return orig_access ? orig_access(path, mode) : -1;
}
static int my_kill(pid_t pid, int sig) {
    if (pid == getpid()) return 0;
    return orig_kill ? orig_kill(pid, sig) : -1;
}
static long my_syscall(long number, ...) {
    if (number == SYS_ptrace || number == 26) return 0;
    return 0;
}
static int my_ioctl(int fildes, unsigned long request, ...) { return -1; }
static uint32_t my_dyld_image_count(void) { return orig_dyld_image_count ? orig_dyld_image_count() : 0; }
static const char* my_dyld_get_image_name(uint32_t image_index) {
    const char *name = orig_dyld_get_image_name ? orig_dyld_get_image_name(image_index) : NULL;
    if (name && (strstr(name, "Substrate") || strstr(name, "frida") || strstr(name, "cydia"))) return "";
    return name;
}
static const struct mach_header* my_dyld_get_image_header(uint32_t image_index) { return orig_dyld_get_image_header ? orig_dyld_get_image_header(image_index) : NULL; }
static intptr_t my_dyld_get_image_vmaddr_slide(uint32_t image_index) { return orig_dyld_get_image_vmaddr_slide ? orig_dyld_get_image_vmaddr_slide(image_index) : 0; }
static int my_dladdr(const void *addr, Dl_info *info) { return 0; }
static void* my_mmap(void *addr, size_t len, int prot, int flags, int fd, off_t offset) { return orig_mmap ? orig_mmap(addr, len, prot, flags, fd, offset) : MAP_FAILED; }
static int my_mprotect(void *addr, size_t len, int prot) { return orig_mprotect ? orig_mprotect(addr, len, prot) : -1; }
static int my_munmap(void *addr, size_t len) { return orig_munmap ? orig_munmap(addr, len) : -1; }
static int my_vm_read(vm_map_t target_task, vm_address_t address, vm_size_t size, vm_offset_t *data, mach_msg_type_number_t *dataCnt) { return KERN_FAILURE; }
static int my_vm_remap(vm_map_t target_task, vm_address_t *address, vm_size_t size, vm_offset_t mask, int flags, vm_offset_t src_addr, boolean_t copy, vm_prot_t *protection, vm_prot_t *max_protection, vm_inherit_t inheritance) { return KERN_FAILURE; }
static int my_mach_vm_region_recurse(vm_map_t target_task, mach_vm_address_t *address, mach_vm_size_t *size, natural_t *depth, vm_region_recurse_info_t info, mach_msg_type_number_t *infoCnt) { return KERN_FAILURE; }
static int my_mach_vm_remap(vm_map_t target_task, mach_vm_address_t *address, mach_vm_size_t size, mach_vm_offset_t mask, int flags, vm_map_t src_task, mach_vm_address_t src_address, boolean_t copy, vm_prot_t *cur_protection, vm_prot_t *max_protection, vm_inherit_t inheritance) { return KERN_FAILURE; }
static uint64_t my_mach_absolute_time(void) { return orig_mach_absolute_time ? orig_mach_absolute_time() : 0; }
static kern_return_t my_mach_timebase_info(mach_timebase_info_t info) { return orig_mach_timebase_info ? orig_mach_timebase_info(info) : KERN_FAILURE; }
static mach_msg_return_t my_mach_msg(mach_msg_header_t *msg, mach_msg_option_t option, mach_msg_size_t send_size, mach_msg_size_t rcv_size, mach_port_name_t rcv_name, mach_msg_timeout_t timeout, mach_port_name_t notify) {
    return orig_mach_msg ? orig_mach_msg(msg, option, send_size, rcv_size, rcv_name, timeout, notify) : MACH_SEND_INVALID_DATA;
}
static mach_port_t my_mig_get_reply_port(void) { return orig_mig_get_reply_port ? orig_mig_get_reply_port() : MACH_PORT_NULL; }
static kern_return_t my_vm_deallocate(vm_map_t target_task, vm_address_t address, vm_size_t size) { return orig_vm_deallocate ? orig_vm_deallocate(target_task, address, size) : KERN_FAILURE; }
static kern_return_t my_vm_copy(vm_map_t target_task, vm_address_t source_address, vm_size_t size, vm_address_t dest_address) { return KERN_FAILURE; }

static SCNetworkReachabilityRef my_SCNetworkReachabilityCreateWithAddress(CFAllocatorRef allocator, const struct sockaddr *address) {
    return orig_SCNetworkReachabilityCreateWithAddress ? orig_SCNetworkReachabilityCreateWithAddress(allocator, address) : NULL;
}
static SCNetworkReachabilityRef my_SCNetworkReachabilityCreateWithName(CFAllocatorRef allocator, const char *name) {
    return orig_SCNetworkReachabilityCreateWithName ? orig_SCNetworkReachabilityCreateWithName(allocator, name) : NULL;
}
static Boolean my_SCNetworkReachabilityGetFlags(SCNetworkReachabilityRef target, SCNetworkReachabilityFlags *flags) {
    if (flags) *flags = 0;
    return false;
}
static Boolean my_SCNetworkReachabilitySetCallback(SCNetworkReachabilityRef target, SCNetworkReachabilityCallBack callout, SCNetworkReachabilityContext *context) { return false; }
static Boolean my_SCNetworkReachabilityScheduleWithRunLoop(SCNetworkReachabilityRef target, CFRunLoopRef runLoop, CFStringRef runLoopMode) { return false; }
static Boolean my_SCNetworkReachabilityUnscheduleFromRunLoop(SCNetworkReachabilityRef target, CFRunLoopRef runLoop, CFStringRef runLoopMode) { return false; }
static CFDictionaryRef my_CFNetworkCopySystemProxySettings(void) { return NULL; }
static int my_connect(int socket, const struct sockaddr *address, socklen_t address_len) { return orig_connect ? orig_connect(socket, address, address_len) : -1; }
static int my_socket(int domain, int type, int protocol) { return orig_socket ? orig_socket(domain, type, protocol) : -1; }
static int my_setsockopt(int socket, int level, int option_name, const void *option_value, socklen_t option_len) { return orig_setsockopt ? orig_setsockopt(socket, level, option_name, option_value, option_len) : -1; }
static int my_getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res) {
    return orig_getaddrinfo ? orig_getaddrinfo(node, service, hints, res) : EAI_FAIL;
}
static void my_freeaddrinfo(struct addrinfo *res) { if (orig_freeaddrinfo) orig_freeaddrinfo(res); }
static const char* my_inet_ntop(int af, const void *src, char *dst, socklen_t size) { return orig_inet_ntop ? orig_inet_ntop(af, src, dst, size) : NULL; }
static int my_inet_pton(int af, const char *src, void *dst) { return orig_inet_pton ? orig_inet_pton(af, src, dst) : 0; }
static CFUUIDRef my_CFUUIDCreate(CFAllocatorRef allocator) { return NULL; }
static CFStringRef my_CFUUIDCreateString(CFAllocatorRef allocator, CFUUIDRef uuid) { return CFSTR("00000000-0000-0000-0000-000000000000"); }
static void my_CFRelease(CFTypeRef cf) { if (orig_CFRelease) orig_CFRelease(cf); }
static void my_UIGraphicsBeginImageContextWithOptions(CGSize size, BOOL opaque, CGFloat scale) { }
static UIImage* my_UIGraphicsGetImageFromCurrentImageContext(void) { return nil; }
static void my_UIGraphicsEndImageContext(void) { }
static int my_pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine)(void*), void *arg) {
    return orig_pthread_create ? orig_pthread_create(thread, attr, start_routine, arg) : -1;
}
static pthread_t my_pthread_self(void) { return orig_pthread_self ? orig_pthread_self() : 0; }
static int my_pthread_setname_np(const char *name) {
    if (name && strstr(name, "frida")) return 0;
    return orig_pthread_setname_np ? orig_pthread_setname_np(name) : -1;
}
static int my_pthread_getname_np(pthread_t thread, char *name, size_t len) {
    int ret = orig_pthread_getname_np ? orig_pthread_getname_np(thread, name, len) : -1;
    if (ret == 0 && name && strstr(name, "frida")) memset(name, 0, len);
    return ret;
}
static int my_pthread_mutex_lock(pthread_mutex_t *mutex) { return orig_pthread_mutex_lock ? orig_pthread_mutex_lock(mutex) : -1; }
static int my_pthread_mutex_unlock(pthread_mutex_t *mutex) { return orig_pthread_mutex_unlock ? orig_pthread_mutex_unlock(mutex) : -1; }
static int my_pthread_mutex_trylock(pthread_mutex_t *mutex) { return orig_pthread_mutex_trylock ? orig_pthread_mutex_trylock(mutex) : -1; }
static void my_dispatch_once_f(dispatch_once_t *predicate, void *context, dispatch_function_t function) {
    if (orig_dispatch_once_f) orig_dispatch_once_f(predicate, context, function);
}
static dispatch_semaphore_t my_dispatch_semaphore_create(long value) { return orig_dispatch_semaphore_create ? orig_dispatch_semaphore_create(value) : NULL; }
static long my_dispatch_semaphore_wait(dispatch_semaphore_t dsema, dispatch_time_t timeout) { return orig_dispatch_semaphore_wait ? orig_dispatch_semaphore_wait(dsema, timeout) : 0; }
static long my_dispatch_semaphore_signal(dispatch_semaphore_t dsema) { return orig_dispatch_semaphore_signal ? orig_dispatch_semaphore_signal(dsema) : 0; }
static void my_dispatch_sync(dispatch_queue_t queue, dispatch_block_t block) { if (orig_dispatch_sync) orig_dispatch_sync(queue, block); }

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
// fishhook bindings (full list)
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
        {"task_info", (void *)my_task_info, (void **)&orig_task_info},
        {"pid_for_task", (void *)my_pid_for_task, (void **)&orig_pid_for_task},
        {"getpid", (void *)my_getpid, (void **)&orig_getpid},
        {"getuid", (void *)my_getuid, (void **)&orig_getuid},
        {"stat", (void *)my_stat, (void **)&orig_stat},
        {"access", (void *)my_access, (void **)&orig_access},
        {"kill", (void *)my_kill, (void **)&orig_kill},
        {"syscall", (void *)my_syscall, (void **)&orig_syscall},
        {"ioctl", (void *)my_ioctl, (void **)&orig_ioctl},
        {"dyld_image_count", (void *)my_dyld_image_count, (void **)&orig_dyld_image_count},
        {"dyld_get_image_name", (void *)my_dyld_get_image_name, (void **)&orig_dyld_get_image_name},
        {"dyld_get_image_header", (void *)my_dyld_get_image_header, (void **)&orig_dyld_get_image_header},
        {"dyld_get_image_vmaddr_slide", (void *)my_dyld_get_image_vmaddr_slide, (void **)&orig_dyld_get_image_vmaddr_slide},
        {"dladdr", (void *)my_dladdr, (void **)&orig_dladdr},
        {"mmap", (void *)my_mmap, (void **)&orig_mmap},
        {"mprotect", (void *)my_mprotect, (void **)&orig_mprotect},
        {"munmap", (void *)my_munmap, (void **)&orig_munmap},
        {"vm_read", (void *)my_vm_read, (void **)&orig_vm_read},
        {"vm_remap", (void *)my_vm_remap, (void **)&orig_vm_remap},
        {"mach_vm_region_recurse", (void *)my_mach_vm_region_recurse, (void **)&orig_mach_vm_region_recurse},
        {"mach_vm_remap", (void *)my_mach_vm_remap, (void **)&orig_mach_vm_remap},
        {"mach_absolute_time", (void *)my_mach_absolute_time, (void **)&orig_mach_absolute_time},
        {"mach_timebase_info", (void *)my_mach_timebase_info, (void **)&orig_mach_timebase_info},
        {"mach_msg", (void *)my_mach_msg, (void **)&orig_mach_msg},
        {"mig_get_reply_port", (void *)my_mig_get_reply_port, (void **)&orig_mig_get_reply_port},
        {"vm_deallocate", (void *)my_vm_deallocate, (void **)&orig_vm_deallocate},
        {"vm_copy", (void *)my_vm_copy, (void **)&orig_vm_copy},
        {"SCNetworkReachabilityCreateWithAddress", (void *)my_SCNetworkReachabilityCreateWithAddress, (void **)&orig_SCNetworkReachabilityCreateWithAddress},
        {"SCNetworkReachabilityCreateWithName", (void *)my_SCNetworkReachabilityCreateWithName, (void **)&orig_SCNetworkReachabilityCreateWithName},
        {"SCNetworkReachabilityGetFlags", (void *)my_SCNetworkReachabilityGetFlags, (void **)&orig_SCNetworkReachabilityGetFlags},
        {"SCNetworkReachabilitySetCallback", (void *)my_SCNetworkReachabilitySetCallback, (void **)&orig_SCNetworkReachabilitySetCallback},
        {"SCNetworkReachabilityScheduleWithRunLoop", (void *)my_SCNetworkReachabilityScheduleWithRunLoop, (void **)&orig_SCNetworkReachabilityScheduleWithRunLoop},
        {"SCNetworkReachabilityUnscheduleFromRunLoop", (void *)my_SCNetworkReachabilityUnscheduleFromRunLoop, (void **)&orig_SCNetworkReachabilityUnscheduleFromRunLoop},
        {"CFNetworkCopySystemProxySettings", (void *)my_CFNetworkCopySystemProxySettings, (void **)&orig_CFNetworkCopySystemProxySettings},
        {"connect", (void *)my_connect, (void **)&orig_connect},
        {"socket", (void *)my_socket, (void **)&orig_socket},
        {"setsockopt", (void *)my_setsockopt, (void **)&orig_setsockopt},
        {"getaddrinfo", (void *)my_getaddrinfo, (void **)&orig_getaddrinfo},
        {"freeaddrinfo", (void *)my_freeaddrinfo, (void **)&orig_freeaddrinfo},
        {"inet_ntop", (void *)my_inet_ntop, (void **)&orig_inet_ntop},
        {"inet_pton", (void *)my_inet_pton, (void **)&orig_inet_pton},
        {"CFUUIDCreate", (void *)my_CFUUIDCreate, (void **)&orig_CFUUIDCreate},
        {"CFUUIDCreateString", (void *)my_CFUUIDCreateString, (void **)&orig_CFUUIDCreateString},
        {"CFRelease", (void *)my_CFRelease, (void **)&orig_CFRelease},
        {"UIGraphicsBeginImageContextWithOptions", (void *)my_UIGraphicsBeginImageContextWithOptions, (void **)&orig_UIGraphicsBeginImageContextWithOptions},
        {"UIGraphicsGetImageFromCurrentImageContext", (void *)my_UIGraphicsGetImageFromCurrentImageContext, (void **)&orig_UIGraphicsGetImageFromCurrentImageContext},
        {"UIGraphicsEndImageContext", (void *)my_UIGraphicsEndImageContext, (void **)&orig_UIGraphicsEndImageContext},
        {"pthread_create", (void *)my_pthread_create, (void **)&orig_pthread_create},
        {"pthread_self", (void *)my_pthread_self, (void **)&orig_pthread_self},
        {"pthread_setname_np", (void *)my_pthread_setname_np, (void **)&orig_pthread_setname_np},
        {"pthread_getname_np", (void *)my_pthread_getname_np, (void **)&orig_pthread_getname_np},
        {"pthread_mutex_lock", (void *)my_pthread_mutex_lock, (void **)&orig_pthread_mutex_lock},
        {"pthread_mutex_unlock", (void *)my_pthread_mutex_unlock, (void **)&orig_pthread_mutex_unlock},
        {"pthread_mutex_trylock", (void *)my_pthread_mutex_trylock, (void **)&orig_pthread_mutex_trylock},
        {"dispatch_once_f", (void *)my_dispatch_once_f, (void **)&orig_dispatch_once_f},
        {"dispatch_semaphore_create", (void *)my_dispatch_semaphore_create, (void **)&orig_dispatch_semaphore_create},
        {"dispatch_semaphore_wait", (void *)my_dispatch_semaphore_wait, (void **)&orig_dispatch_semaphore_wait},
        {"dispatch_semaphore_signal", (void *)my_dispatch_semaphore_signal, (void **)&orig_dispatch_semaphore_signal},
        {"dispatch_sync", (void *)my_dispatch_sync, (void **)&orig_dispatch_sync},
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
// Security checks (unchanged)
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
// Show protection alert (new)
// ============================================================================
static void show_protection_alert(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        UIViewController *rootViewController = nil;
        UIWindow *keyWindow = [UIApplication sharedApplication].keyWindow;
        if (keyWindow) {
            rootViewController = keyWindow.rootViewController;
        }
        if (!rootViewController) {
            // محاولة بديلة
            UIApplication *app = [UIApplication sharedApplication];
            if ([app.delegate respondsToSelector:@selector(window)]) {
                UIWindow *delegateWindow = [app.delegate performSelector:@selector(window)];
                if (delegateWindow) {
                    rootViewController = delegateWindow.rootViewController;
                }
            }
        }
        if (rootViewController) {
            UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"تنبيه"
                                                                           message:@"تم تشغيل الحمايه"
                                                                    preferredStyle:UIAlertControllerStyleAlert];
            UIAlertAction *okAction = [UIAlertAction actionWithTitle:@"موافق" style:UIAlertActionStyleDefault handler:nil];
            [alert addAction:okAction];
            [rootViewController presentViewController:alert animated:YES completion:nil];
        } else {
            NSLog(@"[Hook] لم يتم العثور على الواجهة الرئيسية لعرض التنبيه.");
        }
    });
}

// ============================================================================
// Constructor with 20-second delay and alert
// ============================================================================
__attribute__((constructor))
void init_hook() {
    srand((unsigned int)time(NULL));
    
    // تأخير 20 ثانية قبل تفعيل أي شيء
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(50 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        NSLog(@"[Hook] بدء تفعيل الخطافات والحماية بعد مرور 50 ثانية...");
        
        load_real_ptrace();
        perform_security_checks(); // إذا كان مستوى التهديد عالي سينهي التطبيق
        fishhook_bindings();
        swizzle_objc_methods();
        
        // عرض التنبيه للمستخدم
        show_protection_alert();
    });
}
