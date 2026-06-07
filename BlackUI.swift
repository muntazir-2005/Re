import SwiftUI
import UIKit

// MARK: - Objective-C Bridge
@objc(BlackUIBridge)
public class BlackUIBridge: NSObject {
    @objc public static func showProtectionUI() {
        DispatchQueue.main.async {
            // التحقق من أن إصدار النظام iOS 15.0 فأحدث لدعم الواجهة الزجاجية
            if #available(iOS 15.0, *) {
                guard let window = UIApplication.shared.windows.first(where: { $0.isKeyWindow }),
                      let rootVC = window.rootViewController else { return }
                
                var topController = rootVC
                while let presented = topController.presentedViewController {
                    topController = presented
                }
                
                let hostingController = UIHostingController(rootView: MainContainerView())
                hostingController.modalPresentationStyle = .overFullScreen
                hostingController.view.backgroundColor = .clear // ضروري لتأثير الزجاج
                
                topController.present(hostingController, animated: true) {
                    NotificationCenter.default.post(name: NSNotification.Name("BlackProtectionActivated"), object: nil)
                }
            } else {
                // إذا كان النظام قديماً جداً (iOS 14)، ستعمل الحماية في الخلفية فقط بدون الواجهة الرسومية
                print("[SEC] Protection Enabled. Premium UI requires iOS 15.0+")
            }
        }
    }
}

// MARK: - SwiftUI Views (iOS 15.0+)

@available(iOS 15.0, *)
struct MainContainerView: View {
    @State private var showProtectionToast = false
    @State private var isVisible = true
    
    var body: some View {
        if isVisible {
            ZStack(alignment: .top) {
                HomeView(isVisible: $isVisible)
                
                if showProtectionToast {
                    ProtectionToastView()
                        .transition(.move(edge: .top).combined(with: .opacity))
                        .zIndex(1)
                }
            }
            .onReceive(NotificationCenter.default.publisher(for: NSNotification.Name("BlackProtectionActivated"))) { _ in
                withAnimation(.spring(response: 0.5, dampingFraction: 0.6, blendDuration: 0)) {
                    showProtectionToast = true
                }
                
                DispatchQueue.main.asyncAfter(deadline: .now() + 4) {
                    withAnimation(.easeInOut) {
                        showProtectionToast = false
                    }
                }
            }
        }
    }
}

@available(iOS 15.0, *)
struct ProtectionToastView: View {
    var body: some View {
        HStack(spacing: 15) {
            Image(systemName: "shield.checkerboard")
                .font(.system(size: 24, weight: .bold))
                .foregroundColor(.green)
            
            VStack(alignment: .leading, spacing: 2) {
                Text("تم تشغيل الحماية")
                    .font(.headline)
                    .fontWeight(.bold)
                    .foregroundColor(.white)
                Text("BLACK.")
                    .font(.caption)
                    .foregroundColor(.gray)
            }
            Spacer()
        }
        .padding()
        .background(.ultraThinMaterial) // يتطلب iOS 15.0
        .clipShape(RoundedRectangle(cornerRadius: 20, style: .continuous))
        .overlay(
            RoundedRectangle(cornerRadius: 20, style: .continuous)
                .stroke(LinearGradient(colors: [.green.opacity(0.6), .clear], startPoint: .topLeading, endPoint: .bottomTrailing), lineWidth: 1)
        )
        .shadow(color: .green.opacity(0.2), radius: 15, x: 0, y: 10)
        .padding(.horizontal, 20)
        .padding(.top, 40)
    }
}

@available(iOS 15.0, *)
struct HomeView: View {
    @State private var isAnimating = false
    @Binding var isVisible: Bool
    
    var body: some View {
        ZStack {
            Color.black.opacity(0.95).ignoresSafeArea()
            
            Circle()
                .fill(Color.blue.opacity(0.15))
                .frame(width: 300, height: 300)
                .blur(radius: 60)
                .offset(x: -100, y: -200)
            
            Circle()
                .fill(Color.purple.opacity(0.15))
                .frame(width: 300, height: 300)
                .blur(radius: 60)
                .offset(x: 100, y: 200)
            
            VStack(spacing: 40) {
                Spacer()
                
                Text("BLACK")
                    .font(.system(size: 70, weight: .black, design: .rounded))
                    .foregroundStyle( // يتطلب iOS 15.0
                        LinearGradient(
                            colors: [Color.white, Color.gray.opacity(0.6)],
                            startPoint: .top,
                            endPoint: .bottom
                        )
                    )
                    .shadow(color: .white.opacity(isAnimating ? 0.4 : 0.1), radius: isAnimating ? 20 : 5, x: 0, y: 0)
                    .scaleEffect(isAnimating ? 1.02 : 1.0)
                    .animation(.easeInOut(duration: 2).repeatForever(autoreverses: true), value: isAnimating)
                    .onAppear { isAnimating = true }
                
                VStack(spacing: 15) {
                    GlassCardView(icon: "cpu", title: "حالة المحرك", value: "مستقر", color: .green)
                    GlassCardView(icon: "network.badge.shield.half.filled", title: "مراقبة الشبكة", value: "مُفعل", color: .blue)
                    GlassCardView(icon: "memorychip", title: "حماية الذاكرة", value: "نشط", color: .purple)
                }
                .padding(.horizontal, 24)
                
                Spacer()
                
                FloatingTabBar(isVisible: $isVisible)
            }
        }
    }
}

@available(iOS 15.0, *)
struct GlassCardView: View {
    var icon: String; var title: String; var value: String; var color: Color
    var body: some View {
        HStack {
            Image(systemName: icon)
                .font(.system(size: 24, weight: .medium))
                .foregroundColor(color)
                .frame(width: 40)
            Text(title).font(.system(size: 18, weight: .semibold)).foregroundColor(.white)
            Spacer()
            Text(value)
                .font(.system(size: 16, weight: .medium))
                .foregroundColor(color)
                .padding(.horizontal, 12).padding(.vertical, 6)
                .background(color.opacity(0.15)).clipShape(Capsule())
        }
        .padding().background(.ultraThinMaterial)
        .clipShape(RoundedRectangle(cornerRadius: 20, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 20, style: .continuous).stroke(Color.white.opacity(0.1), lineWidth: 1))
    }
}

@available(iOS 15.0, *)
struct FloatingTabBar: View {
    @Binding var isVisible: Bool
    
    var body: some View {
        HStack(spacing: 50) {
            TabBarIcon(icon: "shield.fill", isSelected: true, action: nil)
            TabBarIcon(icon: "gearshape.fill", isSelected: false, action: nil)
            
            TabBarIcon(icon: "xmark.circle.fill", isSelected: false) {
                withAnimation {
                    isVisible = false
                    guard let window = UIApplication.shared.windows.first(where: { $0.isKeyWindow }),
                          let rootVC = window.rootViewController else { return }
                    rootVC.dismiss(animated: true)
                }
            }
        }
        .padding(.vertical, 15).padding(.horizontal, 30)
        .background(.ultraThinMaterial).clipShape(Capsule())
        .overlay(Capsule().stroke(Color.white.opacity(0.1), lineWidth: 1))
        .shadow(color: .black.opacity(0.5), radius: 20, x: 0, y: 10)
        .padding(.bottom, 20)
    }
}

@available(iOS 15.0, *)
struct TabBarIcon: View {
    var icon: String; var isSelected: Bool; var action: (() -> Void)?
    var body: some View {
        Button(action: { action?() }) {
            Image(systemName: icon)
                .font(.system(size: 24))
                .foregroundColor(isSelected ? .white : .gray.opacity(0.6))
                .scaleEffect(isSelected ? 1.1 : 1.0)
                .animation(.spring(), value: isSelected)
        }
    }
}
