# ==========================================
# Advanced Makefile for Mixed C++/Swift Dylib
# ==========================================

# Compilers
CC = xcrun -sdk iphoneos clang
SWIFTC = xcrun -sdk iphoneos swiftc

# Architecture and Target
ARCH = arm64
TARGET = arm64-apple-ios14.0
SDK = $(shell xcrun -sdk iphoneos --show-sdk-path)

# Flags
# (تم رفع الدعم لـ iOS 14 كحد أدنى لدعم واجهات SwiftUI و Dynamic Island features بشكل جيد)
CFLAGS = -arch $(ARCH) -isysroot $(SDK) -miphoneos-version-min=14.0 -fobjc-arc -O2
SWIFTFLAGS = -target $(TARGET) -sdk $(SDK) -O -parse-as-library

FRAMEWORKS = -framework Foundation -framework UIKit -framework LocalAuthentication -framework Security -framework SwiftUI

# Files
OBJC_SRC = ANOGS.mm fishhook.c
SWIFT_SRC = BlackUI.swift

# Objects mapping for C/C++ files
OBJC_OBJ = $(OBJC_SRC:.c=.o)
OBJC_OBJ := $(OBJC_OBJ:.mm=.o)

all: ANOGS.dylib

# Compile C files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Compile Objective-C++ files
%.o: %.mm
	$(CC) $(CFLAGS) -x objective-c++ -c $< -o $@

# Compile Swift and Link Everything together
# نستخدم مترجم swiftc لربط كل شيء لأنه أذكى في التعامل مع مكتبات Swift Runtime
ANOGS.dylib: $(OBJC_OBJ) $(SWIFT_SRC)
	$(SWIFTC) $(SWIFTFLAGS) -emit-library -o $@ $(SWIFT_SRC) $(OBJC_OBJ) -Xlinker -install_name -Xlinker @executable_path/ANOGS.dylib -Xlinker -lc++ $(FRAMEWORKS)

clean:
	rm -f $(OBJC_OBJ) ANOGS.dylib
