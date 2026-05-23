# ============================================================================
# Makefile لبناء مكتبة الـ Hook لنظام iOS (arm64)
# ============================================================================

# اسم الملف البرمجي الخاص بك واسم المكتبة الناتجة
TARGET = final_hook.dylib
SRC = ANOGS.mm

# 1. إعدادات الـ SDK الخاص بـ iOS (تلقائي عبر Xcode)
SYSROOT = $(shell xcrun --sdk iphoneos --show-sdk-path)
CC = $(shell xcrun --sdk iphoneos --find clang++)

# المعمارية المستهدفة (iOS الحديث يعتمد بالكامل على arm64)
ARCH = -arch arm64
MIN_OS = -miphoneos-version-min=14.0

# 2. مسارات مكتبات الطرف الثالث (قم بتعديل هذه المسارات لتطابق مجلداتك)
# هنا نفترض وجود مجلدين باسم dobby و fishhook في نفس مسار المشروع
DOBBY_DIR = ./dobby
FISHHOOK_DIR = ./fishhook
OPENSSL_DIR = ./openssl

# 3. راوبط التضمين (Headers / Include Paths)
CFLAGS = $(ARCH) $(MIN_OS) -isysroot $(SYSROOT) -std=c++17 -O3 \
         -I$(DOBBY_DIR)/include \
         -I$(FISHHOOK_DIR) \
         -I$(OPENSSL_DIR)/include

# 4. روابط المكتبات الثابتة والديناميكية (Linker Flags)
# نقوم بربط المكتبات كـ Static (.a) أو Dynamic (.dylib) وحقن الـ Frameworks الرسمية
LDFLAGS = -dynamiclib \
          -L$(DOBBY_DIR)/lib -ldobby \
          -L$(OPENSSL_DIR)/lib -lssl -lcrypto \
          -framework Foundation \
          -framework Security \
          -framework LocalAuthentication \
          -framework UIKit \
          -framework CoreFoundation \
          -framework CommonCrypto

# 5. ملفات كود fishhook (لأنها غالباً تُدمج مباشرة ككود مصدري)
# إذا كانت fishhook عبارة عن ملفات .c في مشروعك، سيتم بناؤها تلقائياً مع المشروع
FISHHOOK_SRC = $(FISHHOOK_DIR)/fishhook.c

# ============================================================================
# أوامر البناء (Build Rules)
# ============================================================================

all: $(TARGET)

$(TARGET): $(SRC)
	@echo "[+] جاري بناء المكتبة الديناميكية لنظام iOS..."
	$(CC) $(CFLAGS) $(LDFLAGS) $(SRC) $(FISHHOOK_SRC) -o $(TARGET)
	@echo "[✓] تم البناء بنجاح: $(TARGET)"

clean:
	@echo "[-] جاري تنظيف مخلفات البناء..."
	rm -f $(TARGET)

.PHONY: all clean
