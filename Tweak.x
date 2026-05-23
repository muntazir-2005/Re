#import <Foundation/Foundation.h>
#import <fcntl.h>
#import <unistd.h>
#import "fishhook.h"

#define XOR_KEY 0x5A

// Function prototypes
NSString *decryptString(const unsigned char *encryptedStr, int length);
static int (*orig_open)(const char *, int, ...);

// Example decryption
NSString *decryptString(const unsigned char *encryptedStr, int length) {
    NSMutableString *decryptedString = [NSMutableString stringWithCapacity:length];
    for (int i = 0; i < length; i++) {
        [decryptedString appendFormat:@"%c", encryptedStr[i] ^ XOR_KEY];
    }
    return decryptedString;
}

// Hooked function
int my_open(const char *path, int oflag, ...) {
    if (orig_open) {
        if (strstr(path, "ShadowTrackerExtra/Saved/")) {
            return orig_open("/dev/null", oflag);
        }
        return orig_open(path, oflag);
    }
    return -1;
}

// Safe Initialization Hook
__attribute__((constructor))
static void initialize_bypass(void) {
    orig_open = (int (*)(const char *, int, ...))dlsym(RTLD_DEFAULT, "open");
    rebind_symbols((struct rebinding[1]){
        {"open", my_open, (void *)&orig_open}
    }, 1);
}
