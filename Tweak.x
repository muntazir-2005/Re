#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import "fishhook.h"
#import <sys/sysctl.h>
#import <sys/utsname.h>
#import <dlfcn.h>

// ==================== مؤشرات أصلية ====================
static int (*orig_sysctl)(int *, u_int, void *, size_t *, void *, size_t);
static int (*orig_sysctlbyname)(const char *, void *, size_t *, void *, size_t);
static char* (*orig_getenv)(const char *);
static int (*orig_uname)(struct utsname *);

// دوال بديلة بسيطة جداً
static int _sysctl_h(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    if (namelen >= 2 && name[0] == CTL_KERN && name[1] == KERN_PROC) return -1;
    return orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen);
}

static int _sysctlbyname_h(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    if (name && strstr(name, "proc")) return -1;
    return orig_sysctlbyname(name, oldp, oldlenp, newp, newlen);
}

static char* _getenv_h(const char *name) {
    if (name && strcmp(name, "DYLD_INSERT_LIBRARIES") == 0) return NULL;
    return orig_getenv(name);
}

static int _uname_h(struct utsname *buf) {
    int ret = orig_uname(buf);
    if (ret == 0 && buf) {
        strlcpy(buf->machine, "iPhone15,3", sizeof(buf->machine));
        strlcpy(buf->release, "22.4.0", sizeof(buf->release));
    }
    return ret;
}

__attribute__((constructor))
static void _init() {
    @autoreleasepool {
        NSLog(@"[ANOGS-DIAG] ✅ Stage 0: Library loaded!");

        // المرحلة 1: ربط getenv فقط (آمن)
        NSLog(@"[ANOGS-DIAG] 🔍 Stage 1: Hooking getenv...");
        struct rebinding r1 = {"getenv", _getenv_h, (void**)&orig_getenv};
        rebind_symbols(&r1, 1);
        NSLog(@"[ANOGS-DIAG] ✅ Stage 1 OK");

        // المرحلة 2: ربط sysctl
        NSLog(@"[ANOGS-DIAG] 🔍 Stage 2: Hooking sysctl...");
        struct rebinding r2 = {"sysctl", _sysctl_h, (void**)&orig_sysctl};
        rebind_symbols(&r2, 1);
        NSLog(@"[ANOGS-DIAG] ✅ Stage 2 OK");

        // المرحلة 3: ربط sysctlbyname
        NSLog(@"[ANOGS-DIAG] 🔍 Stage 3: Hooking sysctlbyname...");
        struct rebinding r3 = {"sysctlbyname", _sysctlbyname_h, (void**)&orig_sysctlbyname};
        rebind_symbols(&r3, 1);
        NSLog(@"[ANOGS-DIAG] ✅ Stage 3 OK");

        // المرحلة 4: ربط uname
        NSLog(@"[ANOGS-DIAG] 🔍 Stage 4: Hooking uname...");
        struct rebinding r4 = {"uname", _uname_h, (void**)&orig_uname};
        rebind_symbols(&r4, 1);
        NSLog(@"[ANOGS-DIAG] ✅ Stage 4 OK");

        NSLog(@"[ANOGS-DIAG] 🎉 All fishhook tests passed!");
    }
}
