#import <stdio.h>
#import <string.h>
#import <unistd.h>
#import <stdlib.h>
#import <sys/stat.h>
#import <sys/sysctl.h>
#import <sys/utsname.h>
#import <dlfcn.h>
#import <mach/mach.h>
#import <mach/mach_time.h>
#import <mach-o/dyld.h>
#import <TargetConditionals.h>
#import <sys/param.h>
#import <sys/mount.h>
#import <Security/Security.h>
#import <Security/SecKey.h>
#import <time.h>
#import <dispatch/dispatch.h>
#import <UIKit/UIKit.h>
#import <SystemConfiguration/SystemConfiguration.h>
#import <objc/runtime.h>
#import <objc/message.h>

#if TARGET_OS_IPHONE
#import <LocalAuthentication/LocalAuthentication.h>
#endif

#include "fishhook.h"

// تعريف SYS_ptrace لـ arm64 إذا لم يكن موجوداً
#ifndef SYS_ptrace
    #ifdef __arm64__
        #define SYS_ptrace 117
    #else
        #define SYS_ptrace 26
    #endif
#endif

// ============================================================================
// حماية ptrace عبر استدعاء ديناميكي
// ============================================================================
#define PT_DENY_ATTACH 31
typedef int (*ptrace_ptr_t)(int, pid_t, caddr_t, int);
static ptrace_ptr_t real_ptrace = NULL;
static void load_real_ptrace(void) {
    if (!real_ptrace)
        real_ptrace = (ptrace_ptr_t)dlsym(RTLD_DEFAULT, "ptrace");
}
static int my_ptrace(int request, pid_t pid, caddr_t addr, int data) {
    if (request == PT_DENY_ATTACH) return 0;
    load_real_ptrace();
    return real_ptrace ? real_ptrace(request, pid, addr, data) : 0;
}

// ============================================================================
// Hook للدوال التي تفحص الـ debugger والملفات
// ============================================================================
static int (*orig_sysctl)(int *, u_int, void *, size_t *, void *, size_t);
static int my_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    int ret = orig_sysctl ? orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen) : 0;
    if (ret == 0 && oldp && namelen == 4 && name[0] == CTL_KERN && name[1] == KERN_PROC && name[2] == KERN_PROC_PID) {
        struct kinfo_proc *kp = (struct kinfo_proc *)oldp;
        kp->kp_proc.p_flag &= ~P_TRACED;
    }
    return ret;
}

static int (*orig_sysctlbyname)(const char *, void *, size_t *, void *, size_t);
static int my_sysctlbyname(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    if (oldp && oldlenp && (strstr(name, "debug") || strstr(name, "kern.proc"))) {
        memset(oldp, 0, *oldlenp);
        return 0;
    }
    return orig_sysctlbyname ? orig_sysctlbyname(name, oldp, oldlenp, newp, newlen) : 0;
}

static int (*orig_proc_regionfilename)(int, uint64_t, void *, uint32_t);
static int my_proc_regionfilename(int pid, uint64_t address, void *buffer, uint32_t bufferSize) { return -1; }

static int (*orig_task_info)(mach_port_t, int, task_info_t, mach_msg_type_number_t *);
static int my_task_info(mach_port_t task, int flavor, task_info_t info, mach_msg_type_number_t *count) {
    return orig_task_info ? orig_task_info(task, flavor, info, count) : KERN_FAILURE;
}

static int (*orig_pid_for_task)(mach_port_t, int *);
static int my_pid_for_task(mach_port_t task, int *pid) { return KERN_FAILURE; }

static pid_t (*orig_getpid)(void);
static pid_t my_getpid(void) { return orig_getpid ? orig_getpid() : getpid(); }

static uid_t (*orig_getuid)(void);
static uid_t my_getuid(void) { return orig_getuid ? orig_getuid() : getuid(); }

static int (*orig_stat)(const char *, struct stat *);
static int my_stat(const char *path, struct stat *buf) {
    if (orig_stat) return orig_stat(path, buf);
    return stat(path, buf);
}

static int (*orig_access)(const char *, int);
static int my_access(const char *path, int mode) {
    const char *jbPaths[] = {"/Applications/Cydia.app", "/bin/bash", "/usr/sbin/sshd", "/etc/apt", NULL};
    for (int i = 0; jbPaths[i]; i++) {
        if (strcmp(path, jbPaths[i]) == 0) return -1;
    }
    return orig_access ? orig_access(path, mode) : access(path, mode);
}

static int (*orig_kill)(pid_t, int);
static int my_kill(pid_t pid, int sig) {
    if (pid == getpid() && (sig == SIGSTOP || sig == SIGTRAP))
        return 0;
    return orig_kill ? orig_kill(pid, sig) : kill(pid, sig);
}

static long (*orig_syscall)(long, ...);
static long my_syscall(long number, ...) {
    if (number == SYS_ptrace) return 0;
    return orig_syscall ? orig_syscall(number) : -1;
}

static int (*orig_ioctl)(int, unsigned long, ...);
static int my_ioctl(int fd, unsigned long request, ...) { return -1; }

static uint32_t (*orig_dyld_image_count)(void);
static uint32_t my_dyld_image_count(void) { return orig_dyld_image_count ? orig_dyld_image_count() : 0; }

static const char* (*orig_dyld_get_image_name)(uint32_t);
static const char* my_dyld_get_image_name(uint32_t index) {
    return orig_dyld_get_image_name ? orig_dyld_get_image_name(index) : NULL;
}

static const struct mach_header* (*orig_dyld_get_image_header)(uint32_t);
static const struct mach_header* my_dyld_get_image_header(uint32_t index) {
    return orig_dyld_get_image_header ? orig_dyld_get_image_header(index) : NULL;
}

static intptr_t (*orig_dyld_get_image_vmaddr_slide)(uint32_t);
static intptr_t my_dyld_get_image_vmaddr_slide(uint32_t index) { return 0; }

static void* (*orig_dlopen)(const char *, int);
static void* my_dlopen(const char *path, int mode) {
    if (path && (strstr(path, "frida") || strstr(path, "substrate"))) return NULL;
    return orig_dlopen ? orig_dlopen(path, mode) : NULL;
}

static void* (*orig_dlsym)(void *, const char *);
static void* my_dlsym(void *handle, const char *symbol) {
    if (symbol && (strstr(symbol, "ptrace") || strstr(symbol, "sysctl") || strstr(symbol, "task_for_pid")))
        return NULL;
    return orig_dlsym ? orig_dlsym(handle, symbol) : NULL;
}

static int (*orig_dladdr)(const void *, Dl_info *);
static int my_dladdr(const void *addr, Dl_info *info) { return 0; }

static void* (*orig_mmap)(void *, size_t, int, int, int, off_t);
static void* my_mmap(void *addr, size_t len, int prot, int flags, int fd, off_t offset) {
    if (flags & MAP_JIT) flags &= ~MAP_JIT;
    return orig_mmap ? orig_mmap(addr, len, prot, flags, fd, offset) : MAP_FAILED;
}

static int (*orig_mprotect)(void *, size_t, int);
static int my_mprotect(void *addr, size_t len, int prot) {
    return orig_mprotect ? orig_mprotect(addr, len, prot) : 0;
}

static int (*orig_munmap)(void *, size_t);
static int my_munmap(void *addr, size_t len) {
    return orig_munmap ? orig_munmap(addr, len) : 0;
}

static int (*orig_vm_protect)(vm_map_t, vm_address_t, vm_size_t, boolean_t, vm_prot_t);
static int my_vm_protect(vm_map_t task, vm_address_t addr, vm_size_t size, boolean_t set_max, vm_prot_t prot) {
    return KERN_SUCCESS;
}

static int (*orig_vm_read)(vm_map_t, vm_address_t, vm_size_t, vm_offset_t *, mach_msg_type_number_t *);
static int my_vm_read(vm_map_t task, vm_address_t addr, vm_size_t size, vm_offset_t *data, mach_msg_type_number_t *outCnt) {
    return KERN_FAILURE;
}

static int (*orig_vm_write)(vm_map_t, vm_address_t, vm_offset_t, mach_msg_type_number_t);
static int my_vm_write(vm_map_t task, vm_address_t addr, vm_offset_t data, mach_msg_type_number_t count) {
    return KERN_FAILURE;
}

static int (*orig_vm_remap)(vm_map_t, vm_address_t *, vm_size_t, vm_address_t, int, vm_map_t, vm_address_t, boolean_t, vm_prot_t, vm_prot_t, vm_inherit_t);
static int my_vm_remap(vm_map_t target_task, vm_address_t *address, vm_size_t size, vm_address_t mask, int flags, vm_map_t src_task, vm_address_t src_address, boolean_t copy, vm_prot_t *cur_protection, vm_prot_t *max_protection, vm_inherit_t inheritance) {
    return KERN_FAILURE;
}

static kern_return_t (*orig_mach_vm_region_recurse)(vm_map_t, mach_vm_address_t *, mach_vm_size_t *, mach_vm_address_t *, vm_region_recurse_info_t, mach_msg_type_number_t *);
static kern_return_t my_mach_vm_region_recurse(vm_map_t task, mach_vm_address_t *address, mach_vm_size_t *size, mach_vm_address_t *object_name, vm_region_recurse_info_t info, mach_msg_type_number_t *count) {
    return KERN_FAILURE;
}

static kern_return_t (*orig_mach_vm_remap)(vm_map_t, mach_vm_address_t *, mach_vm_size_t, mach_vm_address_t, int, vm_map_t, mach_vm_address_t, boolean_t, vm_prot_t *, vm_prot_t *, vm_inherit_t);
static kern_return_t my_mach_vm_remap(vm_map_t target_task, mach_vm_address_t *address, mach_vm_size_t size, mach_vm_address_t mask, int flags, vm_map_t src_task, mach_vm_address_t src_address, boolean_t copy, vm_prot_t *cur_protection, vm_prot_t *max_protection, vm_inherit_t inheritance) {
    return KERN_FAILURE;
}

static uint64_t (*orig_mach_absolute_time)(void);
static uint64_t my_mach_absolute_time(void) {
    return orig_mach_absolute_time ? orig_mach_absolute_time() : 0;
}

static kern_return_t (*orig_mach_timebase_info)(mach_timebase_info_t);
static kern_return_t my_mach_timebase_info(mach_timebase_info_t info) {
    if (orig_mach_timebase_info) return orig_mach_timebase_info(info);
    if (info) { info->numer = 1; info->denom = 1; }
    return KERN_SUCCESS;
}

static mach_msg_return_t (*orig_mach_msg)(mach_msg_header_t *, mach_msg_option_t, mach_msg_size_t, mach_msg_size_t, mach_port_t, mach_msg_timeout_t, mach_port_t);
static mach_msg_return_t my_mach_msg(mach_msg_header_t *msg, mach_msg_option_t option, mach_msg_size_t send_size, mach_msg_size_t rcv_size, mach_port_t rcv_name, mach_msg_timeout_t timeout, mach_port_t notify) {
    return MACH_SEND_INVALID_DATA;
}

static mach_port_t (*orig_mig_get_reply_port)(void);
static mach_port_t my_mig_get_reply_port(void) { return MACH_PORT_NULL; }

static kern_return_t (*orig_vm_deallocate)(vm_map_t, vm_address_t, vm_size_t);
static kern_return_t my_vm_deallocate(vm_map_t task, vm_address_t address, vm_size_t size) { return KERN_SUCCESS; }

static kern_return_t (*orig_vm_copy)(vm_map_t, vm_address_t, vm_size_t, vm_address_t);
static kern_return_t my_vm_copy(vm_map_t task, vm_address_t src, vm_size_t size, vm_address_t dst) { return KERN_FAILURE; }

static SCNetworkReachabilityRef (*orig_SCNetworkReachabilityCreateWithAddress)(CFAllocatorRef, const struct sockaddr *);
static SCNetworkReachabilityRef my_SCNetworkReachabilityCreateWithAddress(CFAllocatorRef allocator, const struct sockaddr *address) {
    return NULL;
}

static SCNetworkReachabilityRef (*orig_SCNetworkReachabilityCreateWithName)(CFAllocatorRef, const char *);
static SCNetworkReachabilityRef my_SCNetworkReachabilityCreateWithName(CFAllocatorRef allocator, const char *name) {
    return NULL;
}

static Boolean (*orig_SCNetworkReachabilityGetFlags)(SCNetworkReachabilityRef, SCNetworkReachabilityFlags *);
static Boolean my_SCNetworkReachabilityGetFlags(SCNetworkReachabilityRef target, SCNetworkReachabilityFlags *flags) {
    if (flags) *flags = kSCNetworkReachabilityFlagsReachable;
    return true;
}

static Boolean (*orig_SCNetworkReachabilitySetCallback)(SCNetworkReachabilityRef, SCNetworkReachabilityCallBack, SCNetworkReachabilityContext *);
static Boolean my_SCNetworkReachabilitySetCallback(SCNetworkReachabilityRef target, SCNetworkReachabilityCallBack callback, SCNetworkReachabilityContext *context) {
    return false;
}

static Boolean (*orig_SCNetworkReachabilityScheduleWithRunLoop)(SCNetworkReachabilityRef, CFRunLoopRef, CFStringRef);
static Boolean my_SCNetworkReachabilityScheduleWithRunLoop(SCNetworkReachabilityRef target, CFRunLoopRef runLoop, CFStringRef runLoopMode) {
    return false;
}

static Boolean (*orig_SCNetworkReachabilityUnscheduleFromRunLoop)(SCNetworkReachabilityRef, CFRunLoopRef, CFStringRef);
static Boolean my_SCNetworkReachabilityUnscheduleFromRunLoop(SCNetworkReachabilityRef target, CFRunLoopRef runLoop, CFStringRef runLoopMode) {
    return false;
}

static CFArrayRef (*orig_CFNetworkCopySystemProxySettings)(void);
static CFArrayRef my_CFNetworkCopySystemProxySettings(void) { return NULL; }

static int (*orig_connect)(int, const struct sockaddr *, socklen_t);
static int my_connect(int socket, const struct sockaddr *address, socklen_t address_len) { return -1; }

static int (*orig_socket)(int, int, int);
static int my_socket(int domain, int type, int protocol) {
    return orig_socket ? orig_socket(domain, type, protocol) : -1;
}

static int (*orig_setsockopt)(int, int, int, const void *, socklen_t);
static int my_setsockopt(int socket, int level, int option_name, const void *option_value, socklen_t option_len) {
    if (level == SOL_SOCKET && option_name == SO_DEBUG) return 0;
    return orig_setsockopt ? orig_setsockopt(socket, level, option_name, option_value, option_len) : -1;
}

static int (*orig_getaddrinfo)(const char *, const char *, const struct addrinfo *, struct addrinfo **);
static int my_getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res) {
    return -1;
}

static void (*orig_freeaddrinfo)(struct addrinfo *);
static void my_freeaddrinfo(struct addrinfo *res) { }

static const char* (*orig_inet_ntop)(int, const void *, char *, socklen_t);
static const char* my_inet_ntop(int af, const void *src, char *dst, socklen_t size) {
    if (orig_inet_ntop) return orig_inet_ntop(af, src, dst, size);
    return "0.0.0.0";
}

static int (*orig_inet_pton)(int, const char *, void *);
static int my_inet_pton(int af, const char *src, void *dst) { return 0; }

static OSStatus (*orig_SecItemAdd)(CFDictionaryRef, CFTypeRef *);
static OSStatus my_SecItemAdd(CFDictionaryRef attributes, CFTypeRef *result) { return errSecDuplicateItem; }

static OSStatus (*orig_SecItemCopyMatching)(CFDictionaryRef, CFTypeRef *);
static OSStatus my_SecItemCopyMatching(CFDictionaryRef query, CFTypeRef *result) { return errSecItemNotFound; }

static OSStatus (*orig_SecItemDelete)(CFDictionaryRef);
static OSStatus my_SecItemDelete(CFDictionaryRef query) { return errSecSuccess; }

static CFUUIDRef (*orig_CFUUIDCreate)(CFAllocatorRef);
static CFUUIDRef my_CFUUIDCreate(CFAllocatorRef allocator) { return NULL; }

static CFStringRef (*orig_CFUUIDCreateString)(CFAllocatorRef, CFUUIDRef);
static CFStringRef my_CFUUIDCreateString(CFAllocatorRef allocator, CFUUIDRef uuid) {
    return CFStringCreateWithCString(allocator, "00000000-0000-0000-0000-000000000000", kCFStringEncodingUTF8);
}

static void (*orig_CFRelease)(CFTypeRef);
static void my_CFRelease(CFTypeRef cf) { if (orig_CFRelease) orig_CFRelease(cf); }

static void (*orig_UIGraphicsBeginImageContextWithOptions)(CGSize, BOOL, CGFloat);
static void my_UIGraphicsBeginImageContextWithOptions(CGSize size, BOOL opaque, CGFloat scale) { }

static UIImage* (*orig_UIGraphicsGetImageFromCurrentImageContext)(void);
static UIImage* my_UIGraphicsGetImageFromCurrentImageContext(void) { return nil; }

static void (*orig_UIGraphicsEndImageContext)(void);
static void my_UIGraphicsEndImageContext(void) { }

static int (*orig_pthread_create)(pthread_t *, const pthread_attr_t *, void *(*)(void *), void *);
static int my_pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine)(void *), void *arg) {
    return orig_pthread_create ? orig_pthread_create(thread, attr, start_routine, arg) : EAGAIN;
}

static pthread_t (*orig_pthread_self)(void);
static pthread_t my_pthread_self(void) { return orig_pthread_self ? orig_pthread_self() : pthread_self(); }

static int (*orig_pthread_setname_np)(const char *);
static int my_pthread_setname_np(const char *name) { return 0; }

static int (*orig_pthread_getname_np)(pthread_t, char *, size_t);
static int my_pthread_getname_np(pthread_t thread, char *name, size_t len) { if (name) name[0] = 0; return 0; }

static int (*orig_pthread_mutex_lock)(pthread_mutex_t *);
static int my_pthread_mutex_lock(pthread_mutex_t *mutex) { return orig_pthread_mutex_lock ? orig_pthread_mutex_lock(mutex) : 0; }

static int (*orig_pthread_mutex_unlock)(pthread_mutex_t *);
static int my_pthread_mutex_unlock(pthread_mutex_t *mutex) { return orig_pthread_mutex_unlock ? orig_pthread_mutex_unlock(mutex) : 0; }

static int (*orig_pthread_mutex_trylock)(pthread_mutex_t *);
static int my_pthread_mutex_trylock(pthread_mutex_t *mutex) { return 0; }

static void (*orig_dispatch_once_f)(dispatch_once_t *, void *, void (*)(void *));
static void my_dispatch_once_f(dispatch_once_t *predicate, void *context, void (*function)(void *)) {
    if (orig_dispatch_once_f) orig_dispatch_once_f(predicate, context, function);
}

static dispatch_semaphore_t (*orig_dispatch_semaphore_create)(long);
static dispatch_semaphore_t my_dispatch_semaphore_create(long value) { return orig_dispatch_semaphore_create ? orig_dispatch_semaphore_create(value) : NULL; }

static long (*orig_dispatch_semaphore_wait)(dispatch_semaphore_t, dispatch_time_t);
static long my_dispatch_semaphore_wait(dispatch_semaphore_t dsema, dispatch_time_t timeout) { return 0; }

static long (*orig_dispatch_semaphore_signal)(dispatch_semaphore_t);
static long my_dispatch_semaphore_signal(dispatch_semaphore_t dsema) { return 0; }

static void (*orig_dispatch_sync)(dispatch_queue_t, dispatch_block_t);
static void my_dispatch_sync(dispatch_queue_t queue, dispatch_block_t block) {
    if (orig_dispatch_sync) orig_dispatch_sync(queue, block);
}

static id (*orig_objc_msgSend)(id, SEL, ...);
static id my_objc_msgSend(id self, SEL _cmd, ...) {
    return orig_objc_msgSend ? orig_objc_msgSend(self, _cmd) : nil;
}

static id (*orig_objc_msgSendSuper2)(struct objc_super *, SEL, ...);
static id my_objc_msgSendSuper2(struct objc_super *super, SEL _cmd, ...) {
    return orig_objc_msgSendSuper2 ? orig_objc_msgSendSuper2(super, _cmd) : nil;
}

static BOOL (*orig_class_addMethod)(Class, SEL, IMP, const char *);
static BOOL my_class_addMethod(Class cls, SEL name, IMP imp, const char *types) {
    return orig_class_addMethod ? orig_class_addMethod(cls, name, imp, types) : NO;
}

static Method (*orig_class_getInstanceMethod)(Class, SEL);
static Method my_class_getInstanceMethod(Class cls, SEL name) { return NULL; }

static Method (*orig_class_getClassMethod)(Class, SEL);
static Method my_class_getClassMethod(Class cls, SEL name) { return NULL; }

static IMP (*orig_method_setImplementation)(Method, IMP);
static IMP my_method_setImplementation(Method m, IMP imp) { return imp; }

static Class (*orig_objc_allocateClassPair)(Class, const char *, size_t);
static Class my_objc_allocateClassPair(Class superclass, const char *name, size_t extraBytes) { return nil; }

static void (*orig_objc_registerClassPair)(Class);
static void my_objc_registerClassPair(Class cls) { }

static void (*orig_objc_disposeClassPair)(Class);
static void my_objc_disposeClassPair(Class cls) { }

static Class (*orig_objc_getClass)(const char *);
static Class my_objc_getClass(const char *name) { return objc_getClass(name); }

static SEL (*orig_sel_registerName)(const char *);
static SEL my_sel_registerName(const char *str) { return sel_registerName(str); }

static SEL (*orig_NSSelectorFromString)(NSString *);
static SEL my_NSSelectorFromString(NSString *str) { return NSSelectorFromString(str); }

static Class (*orig_NSClassFromString)(NSString *);
static Class my_NSClassFromString(NSString *str) { return NSClassFromString(str); }

static void (*orig_NSLog)(NSString *, ...);
static void my_NSLog(NSString *format, ...) {
    if (format && (strstr([format UTF8String], "jailbreak") || strstr([format UTF8String], "debug")))
        return;
    va_list args;
    va_start(args, format);
    NSString *msg = [[NSString alloc] initWithFormat:format arguments:args];
    printf("%s\n", [msg UTF8String]);
    va_end(args);
}

static void (*orig__cxa_throw)(void *, void *, void (*)(void *));
static void my__cxa_throw(void *thrown_object, void *tinfo, void (*dest)(void *)) { }

static void (*orig__cxa_begin_catch)(void *);
static void my__cxa_begin_catch(void *p) { }

static void (*orig__cxa_end_catch)(void);
static void my__cxa_end_catch(void) { }

static void* (*orig__cxa_allocate_exception)(size_t);
static void* my__cxa_allocate_exception(size_t thrown_size) { return NULL; }

static int (*orig__cxa_guard_acquire)(void *);
static int my__cxa_guard_acquire(void *guard) { return 0; }

static void (*orig__cxa_guard_release)(void *);
static void my__cxa_guard_release(void *guard) { }

static void (*orig__cxa_guard_abort)(void *);
static void my__cxa_guard_abort(void *guard) { }

static void (*orig__cxa_pure_virtual)(void);
static void my__cxa_pure_virtual(void) { exit(1); }

static void (*orig__Unwind_Resume)(void *);
static void my__Unwind_Resume(void *exception) { }

// ============================================================================
// ربط الدوال باستخدام fishhook
// ============================================================================
void fishhook_bindings(void) {
    struct rebinding bindings[] = {
        {"ptrace", (void *)my_ptrace, (void **)&real_ptrace},
        {"sysctl", (void *)my_sysctl, (void **)&orig_sysctl},
        {"sysctlbyname", (void *)my_sysctlbyname, (void **)&orig_sysctlbyname},
        {"proc_regionfilename", (void *)my_proc_regionfilename, (void **)&orig_proc_regionfilename},
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
        {"dlopen", (void *)my_dlopen, (void **)&orig_dlopen},
        {"dlsym", (void *)my_dlsym, (void **)&orig_dlsym},
        {"dladdr", (void *)my_dladdr, (void **)&orig_dladdr},
        {"mmap", (void *)my_mmap, (void **)&orig_mmap},
        {"mprotect", (void *)my_mprotect, (void **)&orig_mprotect},
        {"munmap", (void *)my_munmap, (void **)&orig_munmap},
        {"vm_protect", (void *)my_vm_protect, (void **)&orig_vm_protect},
        {"vm_read", (void *)my_vm_read, (void **)&orig_vm_read},
        {"vm_write", (void *)my_vm_write, (void **)&orig_vm_write},
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
        {"SecItemAdd", (void *)my_SecItemAdd, (void **)&orig_SecItemAdd},
        {"SecItemCopyMatching", (void *)my_SecItemCopyMatching, (void **)&orig_SecItemCopyMatching},
        {"SecItemDelete", (void *)my_SecItemDelete, (void **)&orig_SecItemDelete},
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
        {"objc_msgSend", (void *)my_objc_msgSend, (void **)&orig_objc_msgSend},
        {"objc_msgSendSuper2", (void *)my_objc_msgSendSuper2, (void **)&orig_objc_msgSendSuper2},
        {"class_addMethod", (void *)my_class_addMethod, (void **)&orig_class_addMethod},
        {"class_getInstanceMethod", (void *)my_class_getInstanceMethod, (void **)&orig_class_getInstanceMethod},
        {"class_getClassMethod", (void *)my_class_getClassMethod, (void **)&orig_class_getClassMethod},
        {"method_setImplementation", (void *)my_method_setImplementation, (void **)&orig_method_setImplementation},
        {"objc_allocateClassPair", (void *)my_objc_allocateClassPair, (void **)&orig_objc_allocateClassPair},
        {"objc_registerClassPair", (void *)my_objc_registerClassPair, (void **)&orig_objc_registerClassPair},
        {"objc_disposeClassPair", (void *)my_objc_disposeClassPair, (void **)&orig_objc_disposeClassPair},
        {"objc_getClass", (void *)my_objc_getClass, (void **)&orig_objc_getClass},
        {"sel_registerName", (void *)my_sel_registerName, (void **)&orig_sel_registerName},
        {"NSSelectorFromString", (void *)my_NSSelectorFromString, (void **)&orig_NSSelectorFromString},
        {"NSClassFromString", (void *)my_NSClassFromString, (void **)&orig_NSClassFromString},
        {"NSLog", (void *)my_NSLog, (void **)&orig_NSLog},
        {"__cxa_throw", (void *)my__cxa_throw, (void **)&orig__cxa_throw},
        {"__cxa_begin_catch", (void *)my__cxa_begin_catch, (void **)&orig__cxa_begin_catch},
        {"__cxa_end_catch", (void *)my__cxa_end_catch, (void **)&orig__cxa_end_catch},
        {"__cxa_allocate_exception", (void *)my__cxa_allocate_exception, (void **)&orig__cxa_allocate_exception},
        {"__cxa_guard_acquire", (void *)my__cxa_guard_acquire, (void **)&orig__cxa_guard_acquire},
        {"__cxa_guard_release", (void *)my__cxa_guard_release, (void **)&orig__cxa_guard_release},
        {"__cxa_guard_abort", (void *)my__cxa_guard_abort, (void **)&orig__cxa_guard_abort},
        {"__cxa_pure_virtual", (void *)my__cxa_pure_virtual, (void **)&orig__cxa_pure_virtual},
        {"_Unwind_Resume", (void *)my__Unwind_Resume, (void **)&orig__Unwind_Resume},
    };
    rebind_symbols(bindings, sizeof(bindings)/sizeof(bindings[0]));
}

// ============================================================================
// واجهة رسومية بعد 35 ثانية (طريقة آمنة)
// ============================================================================
__attribute__((constructor))
void init_hook(void) {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(35 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        UIWindow *window = [UIApplication sharedApplication].keyWindow;
        UIViewController *rootVC = window.rootViewController;
        if (rootVC) {
            UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"الحماية"
                                                                           message:@"تم تفعيل نظام AntiBan بنجاح"
                                                                    preferredStyle:UIAlertControllerStyleAlert];
            [alert addAction:[UIAlertAction actionWithTitle:@"موافق" style:UIAlertActionStyleDefault handler:nil]];
            [rootVC presentViewController:alert animated:YES completion:nil];
        } else {
            printf("\n********** AntiBan Activated **********\n");
        }
    });
    
    fishhook_bindings();
}
