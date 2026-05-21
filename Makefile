TARGET = iphone:clang:latest:15.0
ARCHS = arm64 arm64e

INSTALL_TARGET_PROCESSES = YourGameExecutable

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = ANOGS
ANOGS_FILES = Tweak.x
ANOGS_FRAMEWORKS = UIKit Security
ANOGS_CFLAGS = -fobjc-arc -I.

include $(THEOS_MAKE_PATH)/tweak.mk
