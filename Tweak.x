#import <Foundation/Foundation.h>
#import <fcntl.h>
#import <unistd.h>
#import <dlfcn.h>          // ضروري لتعريف dlsym و RTLD_DEFAULT
#import "fishhook.h"

#define XOR_KEY 0x5A

// مثال لدالة فك تشفير XOR (يمكن استخدامها لإخفاء النصوص الحساسة)
NSString *decryptString(const unsigned char *encryptedStr, int length) {
    NSMutableString *decryptedString = [NSMutableString stringWithCapacity:length];
    for (int i = 0; i < length; i++) {
        [decryptedString appendFormat:@"%c", encryptedStr[i] ^ XOR_KEY];
    }
    return decryptedString;
}

// المؤشر إلى الدالة الأصلية open
static int (*orig_open)(const char *, int, ...);

// الدالة البديلة التي ستستبدل open
int my_open(const char *path, int oflag, ...) {
    if (orig_open) {
        // إذا كان المسار يحتوي على "ShadowTrackerExtra/Saved/" (مجلد حفظ اللعبة)
        // يتم توجيهه إلى /dev/null لإبطال القراءة/الكتابة
        if (strstr(path, "ShadowTrackerExtra/Saved/")) {
            return orig_open("/dev/null", oflag);
        }
        // غير ذلك، استخدم الدالة الأصلية بشكل طبيعي
        return orig_open(path, oflag);
    }
    // فشل احتياطي
    return -1;
}

// يتم تنفيذها تلقائيًا عند تحميل المكتبة الديناميكية
__attribute__((constructor))
static void initialize_bypass(void) {
    // الحصول على عنوان الدالة الأصلية open
    orig_open = (int (*)(const char *, int, ...))dlsym(RTLD_DEFAULT, "open");
    if (!orig_open) {
        // في حالة فشل العثور على الدالة، يمكن تسجيل خطأ أو الخروج
        NSLog(@"[ANOGS] Failed to find original open function");
        return;
    }
    // إعادة ربط الرمز: أي استدعاء لـ open سيذهب إلى my_open
    rebind_symbols((struct rebinding[1]){
        {"open", my_open, (void *)&orig_open}
    }, 1);
    NSLog(@"[ANOGS] open hook installed successfully");
}
