TARGET = iphone:clang:latest:15.0
ARCHS = arm64 arm64e

INSTALL_TARGET_PROCESSES = YourGameExecutable

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = UltimateBypass
UltimateBypass_FILES = Tweak.x fishhook.c    # إذا كان fishhook.c في الجذر
UltimateBypass_FRAMEWORKS = UIKit Security
UltimateBypass_CFLAGS = -fobjc-arc -I.
UltimateBypass_LDFLAGS =

include $(THEOS_MAKE_PATH)/tweak.mk
