#import <Foundation/Foundation.h>
#import <fcntl.h>
#import <unistd.h>
#import <string.h>
#import <sys/socket.h>
#import <netdb.h>
#import <sys/sysctl.h>
#import <sys/stat.h>
#import <dlfcn.h>
#import "fishhook.h"

// ==========================================
// 1. نظام التشفير الديناميكي (XOR Decryption)
// يمنع أنظمة الحماية من العثور على النصوص المكشوفة داخل ملفك
// ==========================================
#define XOR_KEY 0x5A
static NSString* decryptString(const unsigned char* encryptedStr, int length) {
    unsigned char decrypted[length + 1];
    for (int i = 0; i < length; i++) {
        decrypted[i] = encryptedStr[i] ^ XOR_KEY;
    }
    decrypted[length] = '\0';
    return [NSString stringWithUTF8String:(const char*)decrypted];
}

// دالة مبسطة لفك تشفير C-Strings في الذاكرة لحظياً
static void decryptCString(const unsigned char* encryptedStr, int length, char* output) {
    for (int i = 0; i < length; i++) {
        output[i] = encryptedStr[i] ^ XOR_KEY;
    }
    output[length] = '\0';
}

// ==========================================
// 2. مؤشرات الدوال الأصلية للنظام (Original Pointers)
// ==========================================
static int (*orig_open)(const char *, int, ...);
static int (*orig_access)(const char *, int);
static int (*orig_stat)(const char *restrict, struct stat *restrict);
static int (*orig_getaddrinfo)(const char *, const char *, const struct addrinfo *, struct addrinfo **);
static int (*orig_ptrace)(int, pid_t, caddr_t, int);
static void* (*orig_dlsym)(void *, const char *);

// ==========================================
// 3. الاعتراض الشامل لملفات النظام والسجلات
// ==========================================
BOOL isPathBlocked(const char *path) {
    if (!path) return NO;
    // التحقق من مجلدات السجلات (Logs, MMKV, Gamelet)
    // في بيئة حقيقية، نقوم بتشفير هذه النصوص وتمريرها مفككة هنا
    if (strstr(path, "ShadowTrackerExtra/Saved/") != NULL ||
        strstr(path, "Pandora") != NULL || 
        strstr(path, "Cydia") != NULL) {
        return YES;
    }
    return NO;
}

int my_open(const char *path, int oflag, ...) {
    mode_t mode = 0;
    if (oflag & O_CREAT) {
        va_list ap;
        va_start(ap, oflag);
        mode = va_arg(ap, int);
        va_end(ap);
    }
    if (isPathBlocked(path)) {
        return orig_open("/dev/null", oflag, mode); // توجيه للثقب الأسود
    }
    return orig_open(path, oflag, mode);
}

int my_access(const char *path, int amode) {
    if (isPathBlocked(path)) {
        errno = ENOENT; // إيهام اللعبة أن الملف أو المجلد غير موجود
        return -1;
    }
    return orig_access(path, amode);
}

int my_stat(const char *restrict path, struct stat *restrict buf) {
    if (isPathBlocked(path)) {
        errno = ENOENT;
        return -1;
    }
    return orig_stat(path, buf);
}

// ==========================================
// 4. الحظر المتقدم للشبكات (Advanced Analytics Block)
// ==========================================
int my_getaddrinfo(const char *hostname, const char *servname, const struct addrinfo *hints, struct addrinfo **res) {
    if (hostname) {
        // حظر الاتصال بسيرفرات الحماية والإبلاغ عن الكراش
        if (strstr(hostname, "bugly") || strstr(hostname, "tdm") || strstr(hostname, "crash")) {
            return EAI_NONAME; // حظر تام
        }
    }
    return orig_getaddrinfo(hostname, servname, hints, res);
}

// ==========================================
// 5. حماية من مكافحة الغش وديبوجر (Anti-Anti-Cheat & Anti-Debugger)
// ==========================================
// اللعبة تستخدم ptrace لمنع أي برنامج من فحص ذاكرتها
int my_ptrace(int request, pid_t pid, caddr_t addr, int data) {
    // 31 هو PT_DENY_ATTACH، نظام الحماية يطلبه ليمنع أدوات الهاك من الاتصال
    if (request == 31) { 
        return 0; // تخطي وتزييف العملية وكأنها نجحت دون إغلاق اللعبة
    }
    return orig_ptrace(request, pid, addr, data);
}

// اللعبة تستخدم dlsym للبحث في الذاكرة عن دوال مزيفة مثل دوالنا
void* my_dlsym(void *handle, const char *symbol) {
    if (symbol != NULL) {
        // إذا حاولت اللعبة البحث عن الدالة my_open أو أي دالة خاصة بنا، امنعها
        if (strcmp(symbol, "my_open") == 0 || strcmp(symbol, "my_ptrace") == 0) {
            return NULL;
        }
    }
    return orig_dlsym(handle, symbol);
}

// ==========================================
// 6. حقن النينجا (Stealth Injector)
// ==========================================
__attribute__((constructor))
static void initialize_ultimate_bypass() {
    // تشغيل كود الحماية بشكل مخفي وسريع جداً قبل أن تدرك اللعبة
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0), ^{
        
        rebind_symbols((struct rebinding[6]){
            {"open", my_open, (void *)&orig_open},
            {"access", my_access, (void *)&orig_access},
            {"stat", my_stat, (void *)&orig_stat},
            {"getaddrinfo", my_getaddrinfo, (void *)&orig_getaddrinfo},
            {"ptrace", my_ptrace, (void *)&orig_ptrace},
            {"dlsym", my_dlsym, (void *)&orig_dlsym}
        }, 6);
        
    });
}
