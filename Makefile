CC = xcrun -sdk iphoneos clang
SWIFTC = xcrun -sdk iphoneos swiftc
ARCHS = arm64
SDK = $(shell xcrun -sdk iphoneos --show-sdk-path)

# إعدادات C/C++
CFLAGS = -arch $(ARCHS) -isysroot $(SDK) -miphoneos-version-min=15.0 -fobjc-arc -O2
# إعدادات Swift
SWIFTFLAGS = -target arm64-apple-ios15.0 -sdk $(SDK) -emit-objc-header -emit-objc-header-path ANOGS-Swift.h -parse-as-library
# إعدادات الربط (يجب إضافة مكتبات السويفت الأساسية)
LDFLAGS = -dynamiclib -install_name @executable_path/ANOGS.dylib -lc++ -L/usr/lib/swift
FRAMEWORKS = -framework Foundation -framework UIKit -framework LocalAuthentication -framework Security -framework SwiftUI

SRC_OBJC = ANOGS.mm fishhook.c
SRC_SWIFT = Interface.swift

OBJ = fishhook.o ANOGS.o Interface.o

all: ANOGS.dylib

# ترجمة ملفات السويفت واستخراج ملف الرأس (Header)
Interface.o: $(SRC_SWIFT)
	$(SWIFTC) $(SWIFTFLAGS) -c $< -o $@

# ترجمة Objective-C++
ANOGS.o: ANOGS.mm Interface.o
	$(CC) $(CFLAGS) -x objective-c++ -c $< -o $@

# ترجمة C
fishhook.o: fishhook.c
	$(CC) $(CFLAGS) -c $< -o $@

# دمج الجميع في ملف dylib
ANOGS.dylib: $(OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(FRAMEWORKS)

clean:
	rm -f $(OBJ) ANOGS.dylib ANOGS-Swift.h
