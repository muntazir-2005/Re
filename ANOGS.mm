//  ANOGS.mm
//  Hooking Techniques + GUI (Auto-hide after 5s) – PUBG Guest Fix
//  - تم إلغاء تلاعب Keychain & CCCrypt & SecKey لتجنب كسر التطبيقات.
//  - باقي hooks (ptrace, sysctl, vm_*, dlsym, ...) تعمل للحماية.
//  - واجهة AntiBan تظهر 1s ثم تختفي بعد 5s.

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
#import <UIKit/UIKit.h>
#endif

#include "fishhook.h"

// ptrace – dynamic loading
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

// Environment checks (original pointers – not used in fishhook, kept for completeness)
static bool (*orig_is_jb)(void);
static bool (*orig_ROOTED)(void);
static bool (*orig_DEBUGGER_ATTACHED)(void);
static bool (*orig_isDebuggerAttached)(void);
static bool (*orig_checkJailbreak)(void);
static bool (*orig_hasCydia)(void);
static bool (*orig_isJailbroken)(void);
static bool (*orig_amIBeingDebugged)(void);

// Replacement functions
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

// Environment check replacements (unused)
static bool my_is_jb(void) { return false; }
static bool my_ROOTED(void) { return false; }
static bool my_DEBUGGER_ATTACHED(void) { return false; }
static bool my_isDebuggerAttached(void) { return false; }
static bool my_checkJailbreak(void) { return false; }
static bool my_hasCydia(void) { return false; }
static bool my_isJailbroken_c(void) { return false; }
static bool my_amIBeingDebugged(void) { return false; }

// LAContext swizzling (لا تؤثر على PUBG لكن نحتفظ بها)
static void my_LAContext_evaluatePolicy(id self, SEL _cmd, LAPolicy policy,
                                        NSString *localizedReason,
                                        void(^reply)(BOOL success, NSError *error)) {
    if (reply) reply(YES, nil);
}
static BOOL my_LAContext_canEvaluatePolicy(id self, SEL _cmd, LAPolicy policy, NSError **error) {
    return YES;
}
void swizzle_objc_methods() {
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

// fishhook (بدون Keychain / CCCrypt / SecKey / OpenSSL)
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
        // ملاحظة: تمت إزالة جميع hooks المتعلقة بـ Keychain, CCCrypt, SecKey, OpenSSL
        // لأنها تسبب فشل تسجيل الدخول في PUBG وبعض التطبيقات.
        // الحماية الأساسية (مصحح أخطاء، عمليات الذاكرة) باقية.
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

// ============================================================================
// Environment checks (with global result storage for GUI)
// ============================================================================
static int g_jailbreak_paths = 0;
static int g_cydia = 0;
static int g_dyld_hijack = 0;
static int g_debugger = 0;
static int g_ptrace_deny = 0;
static int g_substrate = 0;
static int g_ssh = 0;
static int g_apt = 0;
static int g_frida = 0;
static int g_debugserver = 0;
static int g_provision = 0;
static int g_env = 0;
static int g_ppid = 0;
static int g_simulator = 0;

int is_simulator() {
#if TARGET_IPHONE_SIMULATOR
    g_simulator = 1; return 1;
#else
    struct utsname systemInfo; uname(&systemInfo);
    if (strcmp(systemInfo.machine, "x86_64") == 0 || strcmp(systemInfo.machine, "i386") == 0) {
        g_simulator = 1; return 1;
    }
    g_simulator = 0; return 0;
#endif
}
int is_jailbroken_paths() {
    const char *paths[] = { "/Applications/Cydia.app", "/Library/MobileSubstrate/MobileSubstrate.dylib", "/bin/bash", "/usr/sbin/sshd", "/etc/apt", "/private/var/lib/apt/", "/private/var/stash", "/usr/libexec/cydia", "/usr/sbin/frida-server", "/usr/bin/ssh", "/var/checkra1n.dmg", "/.bootstrapped", NULL };
    for (int i=0; paths[i]; i++) if (access(paths[i], F_OK) == 0) { g_jailbreak_paths=1; return 1; }
    g_jailbreak_paths=0; return 0;
}
int is_cydia_installed() {
#if TARGET_OS_IPHONE
    Class ls = objc_getClass("LSApplicationWorkspace"); if (ls) {
        SEL dw = sel_registerName("defaultWorkspace"), open = sel_registerName("openApplicationWithBundleID:");
        id ws = ((id(*)(id,SEL))objc_msgSend)((id)ls, dw);
        if (ws) { int o = ((int(*)(id,SEL,id))objc_msgSend)(ws, open, @"com.saurik.Cydia"); g_cydia=o; return o; }
    }
#endif
    g_cydia=0; return 0;
}
int is_dyld_hijacked() { if (getenv("DYLD_INSERT_LIBRARIES")||getenv("DYLD_FORCE_FLAT_NAMESPACE")) { g_dyld_hijack=1; return 1; } g_dyld_hijack=0; return 0; }
int is_debugger_attached() {
    int name[4]={CTL_KERN,KERN_PROC,KERN_PROC_PID,getpid()}; struct kinfo_proc info; size_t sz=sizeof(info); info.kp_proc.p_flag=0;
    if (sysctl(name,4,&info,&sz,NULL,0)==-1) { g_debugger=0; return 0; }
    int r = (info.kp_proc.p_flag & P_TRACED)!=0; g_debugger=r; return r;
}
int ptrace_deny_attach() { load_real_ptrace(); if (!real_ptrace) { g_ptrace_deny=1; return 1; } int r = (real_ptrace(PT_DENY_ATTACH,0,0,0)==-1)?1:0; g_ptrace_deny=r; return r; }
int is_substrate_loaded() { for (uint32_t i=0; i<_dyld_image_count(); i++) { const char *n=_dyld_get_image_name(i); if (strstr(n,"MobileSubstrate")||strstr(n,"Substrate")||strstr(n,"CydiaSubstrate")) { g_substrate=1; return 1; } } g_substrate=0; return 0; }
int is_ssh_running() { int r=(access("/usr/sbin/sshd",F_OK)==0); g_ssh=r; return r; }
int is_apt_installed() { int r=(access("/etc/apt",F_OK)==0); g_apt=r; return r; }
int is_frida_installed() { int r=(access("/usr/sbin/frida-server",F_OK)==0); g_frida=r; return r; }
int is_debugserver_installed() { int r=(access("/Developer/usr/bin/debugserver",F_OK)==0); g_debugserver=r; return r; }
int check_provisioning() {
    FILE *fp=NULL; uint32_t size=0; _NSGetExecutablePath(NULL,&size); char *execPath=(char*)malloc(size); if(!execPath) return 0;
    _NSGetExecutablePath(execPath,&size); char *last=strrchr(execPath,'/');
    if (last) { *last='\0'; char p[MAXPATHLEN]; snprintf(p,sizeof(p),"%s/embedded.mobileprovision",execPath); fp=fopen(p,"r"); }
    free(execPath); if (!fp) { g_provision=0; return 0; }
    fseek(fp,0,SEEK_END); long len=ftell(fp); fseek(fp,0,SEEK_SET);
    char *data=(char*)malloc(len+1); if (!data) { fclose(fp); return 0; }
    fread(data,1,len,fp); fclose(fp); data[len]='\0';
    int is=(strstr(data,"<key>get-task-allow</key><true/>")!=NULL); free(data); g_provision=is; return is;
}
int check_env() { const char *vars[]={"DYLD_PRINT_TO_FILE","DYLD_INSERT_LIBRARIES","CFNETWORK_DIAGNOSTICS","OBJC_DISABLE_VALIDATION",NULL}; for (int i=0; vars[i]; i++) if (getenv(vars[i])) { g_env=1; return 1; } g_env=0; return 0; }
int check_ppid() {
    pid_t ppid=getppid(); char path[256]; snprintf(path,sizeof(path),"/proc/%d/exe",ppid);
    if (access(path,F_OK)==0) { char t[256]; ssize_t l=readlink(path,t,sizeof(t)-1); if (l!=-1) { t[l]='\0'; if (strstr(t,"debugserver")||strstr(t,"lldb")) { g_ppid=1; return 1; } } }
    g_ppid=0; return 0;
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

// ============================================================================
// 🎨 MODERN GUI OVERLAY – يختفي تلقائياً بعد 5 ثوانٍ
// ============================================================================
@interface ANOGSOverlay : NSObject
+ (void)show;
@end

@implementation ANOGSOverlay
+ (void)show {
    dispatch_async(dispatch_get_main_queue(), ^{
        UIWindow *overlayWindow = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
        overlayWindow.windowLevel = UIWindowLevelAlert + 1;
        overlayWindow.backgroundColor = [UIColor clearColor];
        overlayWindow.userInteractionEnabled = NO;
        overlayWindow.rootViewController = [UIViewController new];

        UIView *container = [[UIView alloc] initWithFrame:CGRectMake(10, 50, 300, 400)];
        container.backgroundColor = [[UIColor blackColor] colorWithAlphaComponent:0.7];
        container.layer.cornerRadius = 16;
        container.layer.masksToBounds = YES;

        UILabel *title = [[UILabel alloc] initWithFrame:CGRectMake(0, 10, 300, 30)];
        title.text = @"🛡️ ANOGS AntiBan";
        title.textColor = [UIColor whiteColor];
        title.textAlignment = NSTextAlignmentCenter;
        title.font = [UIFont boldSystemFontOfSize:18];
        [container addSubview:title];

        NSArray *items = @[
            @[@"Jailbreak Paths", @(g_jailbreak_paths)],
            @[@"Cydia", @(g_cydia)],
            @[@"DYLD Hijack", @(g_dyld_hijack)],
            @[@"Debugger", @(g_debugger)],
            @[@"PTrace Deny", @(g_ptrace_deny)],
            @[@"Substrate", @(g_substrate)],
            @[@"SSH", @(g_ssh)],
            @[@"APT", @(g_apt)],
            @[@"Frida", @(g_frida)],
            @[@"Debugserver", @(g_debugserver)],
            @[@"Provisioning", @(g_provision)],
            @[@"Env Vars", @(g_env)],
            @[@"Parent PID", @(g_ppid)],
            @[@"Simulator", @(g_simulator)],
        ];

        int y = 50;
        for (NSArray *item in items) {
            UILabel *label = [[UILabel alloc] initWithFrame:CGRectMake(20, y, 200, 25)];
            label.text = item[0];
            label.textColor = [UIColor whiteColor];
            label.font = [UIFont systemFontOfSize:14];
            [container addSubview:label];

            UIView *dot = [[UIView alloc] initWithFrame:CGRectMake(250, y+5, 14, 14)];
            dot.layer.cornerRadius = 7;
            int status = [item[1] intValue];
            dot.backgroundColor = (status == 0) ? [UIColor greenColor] : [UIColor redColor];
            [container addSubview:dot];
            y += 25;
        }

        [overlayWindow.rootViewController.view addSubview:container];
        overlayWindow.hidden = NO;

        // إخفاء تلقائي بعد 5 ثوانٍ
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(5.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            overlayWindow.hidden = YES;
            overlayWindow = nil;  // إزالة المرجع
        });

        // احتفاظ قوي مؤقت
        static UIWindow *staticWindow = nil;
        staticWindow = overlayWindow;
    });
}
@end

// ============================================================================
// Constructor
// ============================================================================
__attribute__((constructor))
void init_hook() {
    srand((unsigned int)time(NULL));
    load_real_ptrace();
    perform_security_checks();
    fishhook_bindings();
    swizzle_objc_methods();

    // إظهار الواجهة بعد 1 ثانية
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        [ANOGSOverlay show];
    });
}
