# Makefile for ANOGS.dylib
# Assumes fishhook.c is present in the same directory.
# Adjust SDK path if needed.

CC = xcrun -sdk iphoneos clang
ARCHS = arm64
SDK = $(shell xcrun -sdk iphoneos --show-sdk-path)
CFLAGS = -arch arm64 -isysroot $(SDK) -miphoneos-version-min=12.0 -fobjc-arc -O2
LDFLAGS = -dynamiclib -install_name @executable_path/ANOGS.dylib
FRAMEWORKS = -framework Foundation -framework UIKit -framework LocalAuthentication -framework Security
LIBS = -lssl -lcrypto

SRC = ANOGS.mm fishhook.c
OBJ = $(SRC:.c=.o)
OBJ := $(OBJ:.mm=.o)

all: ANOGS.dylib

ANOGS.dylib: $(OBJ)
	$(CC) $(ARCHS) $(LDFLAGS) -o $@ $^ $(FRAMEWORKS) $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.mm
	$(CC) $(CFLAGS) -x objective-c++ -c $< -o $@

clean:
	rm -f $(OBJ) ANOGS.dylib          -framework UIKit \
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
