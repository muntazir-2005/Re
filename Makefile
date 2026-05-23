# Theos Makefile for ANOGS.dylib
TARGET := iphone:clang:latest:12.0
include $(THEOS)/makefiles/common.mk

LIBRARY_NAME = ANOGS
ANOGS_TYPE = dylib
ANOGS_INSTALL_PATH = @executable_path

ANOGS_FILES = ANOGS.mm fishhook.c
ANOGS_FRAMEWORKS = Foundation UIKit LocalAuthentication Security
ANOGS_LIBRARIES = c++   # important for C++ symbols
ANOGS_CFLAGS = -fobjc-arc

include $(THEOS_MAKE_PATH)/library.mk
