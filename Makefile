TARGET = iphone:clang:latest:15.0
ARCHS = arm64 arm64e

INSTALL_TARGET_PROCESSES = YourGameExecutable   # غيّره لاسم التطبيق الحقيقي

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = UltimateBypass

# الملفات الموجودة في الجذر
UltimateBypass_FILES = Tweak.x fishhook.c

UltimateBypass_FRAMEWORKS = UIKit Security
UltimateBypass_CFLAGS = -fobjc-arc -I.    # ليبحث عن fishhook.h في نفس المجلد

include $(THEOS_MAKE_PATH)/tweak.mk
