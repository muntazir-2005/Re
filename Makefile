# ============================================================================
# Makefile متوافق مع Theos لـ tweak ANOGS
# يعتمد على مكتبات fishhook و Dobby و OpenSSL
# ============================================================================

export TARGET = iphone:clang:latest:15.0
ARCHS = arm64 arm64e

# اسم الملف التنفيذي للعبة أو التطبيق المستهدف (غيّره حسب الحاجة)
INSTALL_TARGET_PROCESSES = YourGameExecutable

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = ANOGS

# الملفات المصدرية الأساسية
# ANOGS.mm هو الكود المتكامل الذي يضم جميع الهوكات وطبقات الحماية
# fishhook.c مطلوب لاستخدام fishhook (إن لم يكن متوفراً ضمن مكتبة منفصلة)
ANOGS_FILES = ANOGS.mm fishhook.c

# إطارات العمل (Frameworks) المطلوبة
ANOGS_FRAMEWORKS = UIKit Security LocalAuthentication CoreFoundation Foundation

# أعلام المترجم (C flags)
ANOGS_CFLAGS = -fobjc-arc -I$(THEOS)/include/dobby -I$(THEOS)/include/openssl

# أعلام الرابط (LDFLAGS)
# -ldobby : مكتبة Dobby للـ inline hooking
# -lfishhook : مكتبة fishhook للربط الآمن (إذا كانت متوفرة كمكتبة وليس ملف مصدر)
# -lssl -lcrypto : مكتبات OpenSSL (يجب توفرها ضمن مسار Theos أو SDK)
# -lz : ضغط (قد تحتاجه OpenSSL)
# -lresolv : قد تحتاجه بعض دوال النظام
ANOGS_LDFLAGS = -ldobby -lfishhook -lssl -lcrypto -lz -lresolv

# إذا كانت fishhook تأتي فقط كملف مصدر fishhook.c، فلا حاجة لـ -lfishhook في LDFLAGS.
# في هذه الحالة يمكنك حذف -lfishhook من السطر أعلاه والاكتفاء بـ fishhook.c المذكور في ANOGS_FILES.

# إذا كانت dobby غير موجودة كملف مصدر، بل كمكتبة ثابتة أو ديناميكية،
# فحدد المسار المناسب باستخدام -L. مثال:
# ANOGS_LDFLAGS += -L$(THEOS)/lib -ldobby

include $(THEOS_MAKE_PATH)/tweak.mk
