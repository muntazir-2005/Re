CC = xcrun -sdk iphoneos clang
SWIFTC = xcrun -sdk iphoneos swiftc
ARCHS = arm64
SDK = $(shell xcrun -sdk iphoneos --show-sdk-path)

# إعدادات بيئة C/C++
CFLAGS = -arch $(ARCHS) -isysroot $(SDK) -miphoneos-version-min=15.0 -fobjc-arc -O2

# إعدادات بيئة Swift
SWIFT_TARGET = arm64-apple-ios15.0
SWIFTFLAGS = -target $(SWIFT_TARGET) -sdk $(SDK) -emit-objc-header -emit-objc-header-path ANOGS-Swift.h -parse-as-library

# إطارات العمل المطلوبة
FRAMEWORKS = -framework Foundation -framework UIKit -framework LocalAuthentication -framework Security -framework SwiftUI

SRC_OBJC = ANOGS.mm fishhook.c
SRC_SWIFT = Interface.swift

OBJ = fishhook.o ANOGS.o Interface.o

all: ANOGS.dylib

# 1. ترجمة ملف السويفت وتوليد الهيدر
Interface.o: $(SRC_SWIFT)
	$(SWIFTC) $(SWIFTFLAGS) -c $< -o $@

# 2. ترجمة ملف C++
ANOGS.o: ANOGS.mm Interface.o
	$(CC) $(CFLAGS) -x objective-c++ -c $< -o $@

# 3. ترجمة ملف C
fishhook.o: fishhook.c
	$(CC) $(CFLAGS) -c $< -o $@

# 4. الدمج النهائي باستخدام swiftc بدلاً من clang لحل مشكلة مكتبات التوافق
ANOGS.dylib: $(OBJ)
	$(SWIFTC) -target $(SWIFT_TARGET) -sdk $(SDK) -emit-library -o $@ $^ -Xlinker -install_name -Xlinker @executable_path/ANOGS.dylib -lc++ $(FRAMEWORKS)

clean:
	rm -f $(OBJ) ANOGS.dylib ANOGS-Swift.h
