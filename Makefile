# ============================================================================
# Makefile متوافق مع Theos لـ tweak ANOGS (نسخة مصلحة ومحسنة)
# ============================================================================

export TARGET = iphone:clang:latest:15.0
ARCHS = arm64 arm64e

# اسم الملف التنفيذي للتطبيق أو اللعبة المستهدفة
INSTALL_TARGET_PROCESSES = YourGameExecutable

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = ANOGS

# الملفات المصدرية الأساسية
# نقوم بتضمين fishhook.c مباشرة هنا ليتم تجميعه مع المشروع دون الحاجة لمكتبة خارجية
ANOGS_FILES = ANOGS.mm fishhook.c

# إطارات العمل (Frameworks) المطلوبة من النظام
ANOGS_FRAMEWORKS = UIKit Security LocalAuthentication CoreFoundation Foundation

# أعلام المترجم (Compiler Flags)
# 1. تم إضافة -fno-modules و -fno-cxx-modules لحل مشكلة تعارض dobby.h مع extern "C".
# 2. تم حذف مسار الاستدعاء الخاص بـ openssl لأننا استغنينا عن ملفات الـ Headers الخاصة به.
ANOGS_CFLAGS = -fobjc-arc -fno-modules -fno-cxx-modules -I$(THEOS)/include/dobby

# أعلام الرابط (Linker Flags)
# 1. تم حذف -lssl و -lcrypto لأن الكود المحدث يعتمد على dlsym للحصول على رموز OpenSSL ديناميكياً فلا يتطلب ربطاً وقت التجميع.
# 2. تم حذف -lfishhook لأننا نجمع ملف fishhook.c المصدري مباشرة ضمن المشروع (في سطر ANOGS_FILES).
ANOGS_LDFLAGS = -ldobby -lz -lresolv

# إذا كانت مكتبة dobby موجودة في مسار مخصص داخل الـ SDK، يمكنك فك التعليق عن السطر التالي وتعديله:
# ANOGS_LDFLAGS += -L$(THEOS)/lib

include $(THEOS_MAKE_PATH)/tweak.mk
