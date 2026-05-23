TARGET := iphone:clang:latest:15.0
ARCHS := arm64 arm64e

include $(THEOS)/makefiles/common.mk

# تحويل نوع المشروع إلى مكتبة ديناميكية مخصصة
LIBRARY_NAME = ANOGS

# تضمين ملف السي لـ fishhook الموجود في مجلد مشروعك ليتم بناؤه تلقائياً
ANOGS_FILES = ANOGS.mm fishhook.c
ANOGS_CFLAGS = -fobjc-arc -Wno-unused-variable -Wno-error -I.

# توجيه المفسر للبحث عن libdobby.a في المجلد الحالي (.) وربط الفريموركات المطلوبة
ANOGS_LDFLAGS = -L. -ldobby -framework Foundation -framework Security -framework LocalAuthentication -framework UIKit

include $(THEOS)/makefiles/library.mk
