TARGET := iphone:clang:latest:14.0
include $(THEOS)/makefiles/common.mk

LIBRARY_NAME = ANOGS
ANOGS_TYPE = dylib
ANOGS_INSTALL_PATH = @executable_path

ANOGS_FILES = ANOGS.mm fishhook.c
ANOGS_FRAMEWORKS = Foundation UIKit LocalAuthentication Security
ANOGS_LIBRARIES = c++
ANOGS_CFLAGS = -fobjc-arc -Wno-unused
ANOGS_CODESIGN_FLAGS = -             # تعطيل التوقيع لتجنب خطأ ldid

include $(THEOS_MAKE_PATH)/library.mk
