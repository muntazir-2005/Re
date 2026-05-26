import SwiftUI
import UIKit

// ==========================================
// 1. ربط دالة الـ C++ مع السويفت (C-Bridge)
// ==========================================
// هذا السطر يخبر سويفت بوجود دالة مكتوبة بلغة C/C++ في ملف آخر سيتم ربطها لاحقاً
@_silgen_name("set_protection_state")
public func set_protection_state(_ enabled: Bool)


// ==========================================
// 2. تصميم الواجهة الرسومية (SwiftUI View)
// ==========================================
public struct ProtectionDashboardView: View {
    // متغير حالة الزر
    @State private var isProtectionEnabled = false
    
    // منشئ عام (Public Initializer)
    public init() {}
    
    public var body: some View {
        VStack {
            Text("⚙️ لوحة حماية ANOGS")
                .font(.headline)
                .foregroundColor(.white)
                .padding(.top, 10)
            
            Divider().background(Color.gray)
            
            Toggle("تفعيل الـ Anti-Ban", isOn: $isProtectionEnabled)
                .padding()
                .foregroundColor(.white)
                .onChange(of: isProtectionEnabled) { newValue in
                    // استدعاء دالة الـ C++ لتفعيل/تعطيل الحماية عند ضغط الزر
                    set_protection_state(newValue)
                    print("[ANOGS] Protection state changed to: \(newValue)")
                }
        }
        .frame(width: 280, height: 120)
        .background(Color.black.opacity(0.85)) // خلفية زجاجية سوداء
        .cornerRadius(15)
        .overlay(
            RoundedRectangle(cornerRadius: 15)
                .stroke(Color.green.opacity(isProtectionEnabled ? 1.0 : 0.0), lineWidth: 2)
        )
        // جعل اللوحة قابلة للسحب (Draggable) جزئياً إذا لزم الأمر
        .position(x: UIScreen.main.bounds.width / 2, y: UIScreen.main.bounds.height / 5)
    }
}


// ==========================================
// 3. جسر إظهار الواجهة فوق التطبيق
// ==========================================
@objc(DynamicUIBridge)
public class DynamicUIBridge: NSObject {
    static var protectionWindow: UIWindow?

    @objc public static func showDashboard() {
        DispatchQueue.main.async {
            // البحث عن الشاشة النشطة
            guard let windowScene = UIApplication.shared.connectedScenes
                .first(where: { $0.activationState == .foregroundActive }) as? UIWindowScene else {
                // إعادة المحاولة إذا لم تكن الشاشة جاهزة
                DispatchQueue.main.asyncAfter(deadline: .now() + 1.0) {
                    showDashboard()
                }
                return
            }

            // إنشاء نافذة شفافة عائمة
            let window = UIWindow(windowScene: windowScene)
            window.windowLevel = .alert + 1 // وضعها فوق كل عناصر التطبيق
            window.backgroundColor = .clear
            
            // حقن واجهة SwiftUI داخل النافذة
            let hostingController = UIHostingController(rootView: ProtectionDashboardView())
            hostingController.view.backgroundColor = .clear
            
            window.rootViewController = hostingController
            window.makeKeyAndVisible()
            
            // الاحتفاظ بالنافذة في الذاكرة لمنع اختفائها
            self.protectionWindow = window
        }
    }
}
