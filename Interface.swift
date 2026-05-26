import SwiftUI
import UIKit

// استخدام @objc(DynamicUIBridge) مهم جداً لكي يتعرف عليه كود الـ Objective-C بدون مشاكل مساحة الأسماء
@objc(DynamicUIBridge)
public class DynamicUIBridge: NSObject {
    static var protectionWindow: UIWindow?

    @objc public static func showDashboard() {
        DispatchQueue.main.async {
            guard let windowScene = UIApplication.shared.connectedScenes
                .first(where: { $0.activationState == .foregroundActive }) as? UIWindowScene else {
                DispatchQueue.main.asyncAfter(deadline: .now() + 1.0) {
                    showDashboard()
                }
                return
            }

            let window = UIWindow(windowScene: windowScene)
            window.windowLevel = .alert + 1 
            window.backgroundColor = .clear
            
            let hostingController = UIHostingController(rootView: ProtectionDashboardView())
            hostingController.view.backgroundColor = .clear
            
            window.rootViewController = hostingController
            window.makeKeyAndVisible()
            
            self.protectionWindow = window
        }
    }
}
