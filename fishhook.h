#ifndef fishhook_h
#define fishhook_h

#include <stddef.h>
#include <stdint.h>

#if !defined(FISHHOOK_EXPORT)
#define FISHHOOK_VISIBILITY __attribute__((visibility("hidden")))
#else
#define FISHHOOK_VISIBILITY __attribute__((visibility("default")))
#endif

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/**
 * @struct rebinding
 * @brief هيكل لإعادة ربط رمز دالة باسم مع استبدال وسجل رسالة للإرجاع.
 */
struct rebinding {
  const char *name;       ///< اسم الرمز المراد تحويره
  void *replacement;      ///< مؤشر إلى الدالة الجديدة التي ستقوم بالاستبدال
  void **replaced;        ///< مؤشر لحفظ الدالة الأصلية (يمكن أن يكون NULL)
};

/**
 * @brief يعيد ربط رموز في جميع الصور المحملة حاليًا وأي صور مستقبلية.
 *
 * عند الاستدعاء المتكرر، يتم دمج الـ rebindings الجديدة مع القوائم الحالية،
 * وأي إعادة ربط جديدة تعطي الأولوية على السابقة.
 *
 * @param rebindings مصفوفة من rebinding structs
 * @param rebindings_nel عدد العناصر في المصفوفة
 * @return 0 عند النجاح، وقيم أخرى عند فشل العملية
 */
FISHHOOK_VISIBILITY
int rebind_symbols(struct rebinding rebindings[], size_t rebindings_nel);

/**
 * @brief يعيد ربط رموز في صورة Mach-O محددة فقط.
 *
 * @param header مؤشر إلى رأس صورة Mach-O
 * @param slide إزاحة الصورة
 * @param rebindings مصفوفة rebinding
 * @param rebindings_nel عدد عناصر المصفوفة
 * @return 0 عند النجاح، وقيم أخرى عند فشل العملية
 */
FISHHOOK_VISIBILITY
int rebind_symbols_image(void *header,
                         intptr_t slide,
                         struct rebinding rebindings[],
                         size_t rebindings_nel);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // fishhook_h