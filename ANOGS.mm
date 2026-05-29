// =============== نظام AntiBan الذكي - إصدار آمن ومتكامل ===============
// يعمل على iOS بدون جيلبريك، لا يسبب كراش، متوافق مع شركة "أريد"

#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <sys/sysctl.h>
#import <sys/stat.h>
#import <unistd.h>
#import <spawn.h>
#import <pthread.h>
#import <objc/runtime.h>
#import <sys/types.h>
#import <fcntl.h>
#import "fishhook.h"   // مكتبة اعتراض دوال C

// ================================================
// 1. قائمة التطبيقات والعمليات والملفات الممنوعة
// ================================================
static NSArray *forbiddenProcesses = nil;
static NSArray *forbiddenPaths = nil;

// ================================================
// 2. اعتراض sysctl (فحص العمليات + تصحيح الأخطاء)
// ================================================
int (*original_sysctl)(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen);

int hooked_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    int ret = original_sysctl(name, namelen, oldp, oldlenp, newp, newlen);
    
    // فحص قائمة العمليات الكلية KERN_PROC_ALL
    if (name[0] == CTL_KERN && name[1] == KERN_PROC && name[2] == KERN_PROC_ALL) {
        if (oldp && oldlenp) {
            struct kinfo_proc *procs = (struct kinfo_proc *)oldp;
            size_t count = *oldlenp / sizeof(struct kinfo_proc);
            struct kinfo_proc *newProcs = (struct kinfo_proc *)malloc(*oldlenp);
            size_t newCount = 0;
            for (size_t i = 0; i < count; i++) {
                NSString *procName = [NSString stringWithUTF8String:procs[i].kp_proc.p_comm];
                if (![forbiddenProcesses containsObject:procName]) {
                    newProcs[newCount++] = procs[i];
                }
            }
            memcpy(procs, newProcs, newCount * sizeof(struct kinfo_proc));
            *oldlenp = newCount * sizeof(struct kinfo_proc);
            free(newProcs);
        }
    }
    
    // فحص عملية محددة (للكشف عن P_TRACED - منع كشف التصحيح)
    if (name[0] == CTL_KERN && name[1] == KERN_PROC && name[2] == KERN_PROC_PID && oldp && oldlenp) {
        struct kinfo_proc *proc = (struct kinfo_proc *)oldp;
        if (*oldlenp == sizeof(struct kinfo_proc)) {
            proc->kp_proc.p_flag &= ~P_TRACED;  // إزالة علامة التتبع
        }
    }
    
    // فحص وجود العمليات مثل P_TRACED عبر sysctl آخر
    if (name[0] == CTL_KERN && name[1] == KERN_PROC && name[2] == KERN_PROC_PID) {
        // تمت المعالجة أعلاه
    }
    
    return ret;
}

// ================================================
// 3. اعتراض ptrace (أدوات مكافحة التصحيح)
// ================================================
int (*original_ptrace)(int request, pid_t pid, caddr_t addr, int data);
int hooked_ptrace(int request, pid_t pid, caddr_t addr, int data) {
    if (request == PT_DENY_ATTACH) {
        // تجاهل طلب منع التصحيح بهدوء
        return 0;
    }
    return original_ptrace(request, pid, addr, data);
}

// ================================================
// 4. اعتراض stat (فحص وجود ملفات/مجلدات)
// ================================================
int (*original_stat)(const char *path, struct stat *buf);
int hooked_stat(const char *path, struct stat *buf) {
    if (path) {
        NSString *pathStr = [NSString stringWithUTF8String:path];
        for (NSString *bad in forbiddenPaths) {
            if ([pathStr hasPrefix:bad]) {
                errno = ENOENT;
                return -1;  // الملف غير موجود
            }
        }
    }
    return original_stat(path, buf);
}

// ================================================
// 5. اعتراض access (فحص الصلاحيات والوجود)
// ================================================
int (*original_access)(const char *path, int mode);
int hooked_access(const char *path, int mode) {
    if (path) {
        NSString *pathStr = [NSString stringWithUTF8String:path];
        for (NSString *bad in forbiddenPaths) {
            if ([pathStr hasPrefix:bad]) {
                errno = ENOENT;
                return -1;
            }
        }
    }
    return original_access(path, mode);
}

// ================================================
// 6. اعتراض fopen (فتح الملفات)
// ================================================
FILE * (*original_fopen)(const char *path, const char *mode);
FILE * hooked_fopen(const char *path, const char *mode) {
    if (path) {
        NSString *pathStr = [NSString stringWithUTF8String:path];
        for (NSString *bad in forbiddenPaths) {
            if ([pathStr hasPrefix:bad]) {
                errno = ENOENT;
                return NULL;
            }
        }
    }
    return original_fopen(path, mode);
}

// ================================================
// 7. اعتراض system() (تنفيذ أوامر خطيرة)
// ================================================
int (*original_system)(const char *command);
int hooked_system(const char *command) {
    return -1;  // منع تنفيذ أي أمر
}

// ================================================
// 8. اعتراض popen()
// ================================================
FILE * (*original_popen)(const char *command, const char *type);
FILE * hooked_popen(const char *command, const char *type) {
    return NULL;  // فشل العملية
}

// ================================================
// 9. اعتراض fork()
// ================================================
pid_t (*original_fork)(void);
pid_t hooked_fork(void) {
    return -1;  // منع إنشاء عمليات جديدة
}

// ================================================
// 10. Swizzling آمن لـ NSFileManager (لإخفاء ملفات من التطبيق)
// ================================================
@implementation NSFileManager (AntiBan)
+ (void)load {
    // لن يتم استدعاؤها لأننا نحقن الكود بعد تحميل الفئة
}
@end

static BOOL (*original_fileExistsAtPath)(id self, SEL _cmd, NSString *path);
static BOOL hooked_fileExistsAtPath(id self, SEL _cmd, NSString *path) {
    for (NSString *bad in forbiddenPaths) {
        if ([path hasPrefix:bad]) {
            return NO;
        }
    }
    return original_fileExistsAtPath(self, _cmd, path);
}

// ================================================
// 11. Swizzling آمن لـ NSProcessInfo (إصدار النظام - بدون كراش!)
// ================================================
static NSOperatingSystemVersion (*original_operatingSystemVersion)(id self, SEL _cmd);
static NSOperatingSystemVersion hooked_operatingSystemVersion(id self, SEL _cmd) {
    // إرجاع نسخة طبيعية (لا حاجة للتزوير هنا)
    return original_operatingSystemVersion(self, _cmd);
}

// ================================================
// 12. دوال مساعدة لتحميل القوائم وتفعيل الاعتراضات
// ================================================
static void setupHooks() {
    // قائمة العمليات الممنوعة (تُضبط حسب احتياج "أريد")
    forbiddenProcesses = @[
        @"Terminal", @"iTerm2", @"zsh", @"bash", @"ssh",
        @"Frida", @"frida-server", @"cycript", @"debugserver",
        @"gdb", @"lldb", @"dtrace"
    ];
    
    // قائمة المسارات الممنوعة (ملفات جيلبريك وأدوات)
    forbiddenPaths = @[
        @"/Applications/Cydia.app",
        @"/Applications/Sileo.app",
        @"/usr/bin/ssh",
        @"/usr/sbin/sshd",
        @"/usr/bin/Frida",
        @"/usr/lib/libsubstrate.dylib",
        @"/Library/MobileSubstrate",
        @"/var/lib/cydia",
        @"/var/tmp/frida"
    ];
    
    // اعتراض sysctl
    struct rebinding sysctl_reb = {"sysctl", hooked_sysctl, (void *)&original_sysctl};
    rebind_symbols((struct rebinding[1]){sysctl_reb}, 1);
    
    // اعتراض ptrace
    struct rebinding ptrace_reb = {"ptrace", hooked_ptrace, (void *)&original_ptrace};
    rebind_symbols(&ptrace_reb, 1);
    
    // اعتراض stat
    struct rebinding stat_reb = {"stat", hooked_stat, (void *)&original_stat};
    rebind_symbols(&stat_reb, 1);
    
    // اعتراض access
    struct rebinding access_reb = {"access", hooked_access, (void *)&original_access};
    rebind_symbols(&access_reb, 1);
    
    // اعتراض fopen
    struct rebinding fopen_reb = {"fopen", hooked_fopen, (void *)&original_fopen};
    rebind_symbols(&fopen_reb, 1);
    
    // اعتراض system
    struct rebinding system_reb = {"system", hooked_system, (void *)&original_system};
    rebind_symbols(&system_reb, 1);
    
    // اعتراض popen
    struct rebinding popen_reb = {"popen", hooked_popen, (void *)&original_popen};
    rebind_symbols(&popen_reb, 1);
    
    // اعتراض fork
    struct rebinding fork_reb = {"fork", hooked_fork, (void *)&original_fork};
    rebind_symbols(&fork_reb, 1);
    
    // Swizzle NSFileManager
    Class fileManagerClass = [NSFileManager class];
    SEL fileExistsSel = @selector(fileExistsAtPath:);
    Method origMethod = class_getInstanceMethod(fileManagerClass, fileExistsSel);
    original_fileExistsAtPath = (void *)method_getImplementation(origMethod);
    method_setImplementation(origMethod, (IMP)hooked_fileExistsAtPath);
    
    // Swizzle NSProcessInfo (باستخدام مؤشر دالة C وليس block)
    Class processInfoClass = [NSProcessInfo class];
    SEL osVersionSel = @selector(operatingSystemVersion);
    Method osMethod = class_getInstanceMethod(processInfoClass, osVersionSel);
    original_operatingSystemVersion = (void *)method_getImplementation(osMethod);
    method_setImplementation(osMethod, (IMP)hooked_operatingSystemVersion);
    
    NSLog(@"[AntiBan] ✅ تم تفعيل جميع الحمايات بدون كراش");
}

// ================================================
// 13. مُنشئ تلقائي عند تحميل المكتبة
// ================================================
__attribute__((constructor))
static void AntiBan_Initialize() {
    @autoreleasepool {
        setupHooks();
        // يمكن إضافة مراقبة مستمرة بسيطة (اختياري)
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 1.0 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
            NSLog(@"[AntiBan] 🛡️ النظام يعمل في الخلفية");
        });
    }
}
