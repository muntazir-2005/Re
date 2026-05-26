// ProtectionView.swift
import SwiftUI
import UIKit

// ربط دالة الـ C
@_silgen_name("set_protection_state")
func setProtectionState(enabled: Bool)

// واجهة التحكم
public struct ProtectionDashboardView: View {
    @State private var isEnabled = false
    @State private var pulseAnimation = false
    
    public init() {}
    
    public var body: some View {
        VStack(spacing: 24) {
            HStack {
                Circle()
                    .fill(isEnabled ? Color.green : Color.red)
                    .frame(width: 12, height: 12)
                    .scaleEffect(pulseAnimation ? 1.2 : 1.0)
                    .onAppear {
                        withAnimation(Animation.easeInOut(duration: 1).repeatForever(autoreverses: true)) {
                            pulseAnimation.toggle()
                        }
                    }
                Text(isEnabled ? "الحماية نشطة" : "الحماية متوقفة")
                    .font(.system(.subheadline, design: .rounded))
                    .fontWeight(.bold)
                    .foregroundColor(.primary)
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 8)
            .background(Capsule().fill(.ultraThinMaterial))
            
            Text("لوحة التحكم الأمنية")
                .font(.system(.title2, design: .rounded))
                .fontWeight(.black)
                .foregroundStyle(LinearGradient(colors: [.primary, .secondary], startPoint: .top, endPoint: .bottom))
            
            Button(action: {
                let generator = UIImpactFeedbackGenerator(style: .heavy)
                generator.impactOccurred()
                withAnimation(.spring(response: 0.4, dampingFraction: 0.6, blendDuration: 0)) {
                    isEnabled.toggle()
                    setProtectionState(enabled: isEnabled)
                }
            }) {
                ZStack {
                    Circle()
                        .fill(isEnabled ?
                              LinearGradient(colors: [Color.green, Color.mint], startPoint: .topLeading, endPoint: .bottomTrailing) :
                              LinearGradient(colors: [Color(.systemGray4), Color(.systemGray5)], startPoint: .topLeading, endPoint: .bottomTrailing))
                        .frame(width: 120, height: 120)
                        .shadow(color: isEnabled ? Color.green.opacity(0.5) : Color.black.opacity(0.1), radius: 20, x: 0, y: 10)
                    Image(systemName: "shield.motion")
                        .font(.system(size: 45, weight: .semibold))
                        .foregroundColor(isEnabled ? .white : .secondary)
                        .rotationEffect(.degrees(isEnabled ? 360 : 0))
                }
            }
            
            VStack(alignment: .leading, spacing: 8) {
                ProtectionRow(title: "تخطي كشف السجن (Jailbreak)", active: isEnabled)
                ProtectionRow(title: "مكافحة حاقن الأدوات (Frida/Substrate)", active: isEnabled)
                ProtectionRow(title: "منع تعقب الملحقات (Anti-Debugger)", active: isEnabled)
                ProtectionRow(title: "منع حقن المكتبات (Anti-Dylib)", active: isEnabled)
            }
            .padding()
            .background(RoundedRectangle(cornerRadius: 16).fill(.italic).opacity(0.05))
        }
        .padding(30)
        .frame(width: 320)
        .background(.ultraThinMaterial)
        .cornerRadius(32)
        .overlay(
            RoundedRectangle(cornerRadius: 32)
                .stroke(LinearGradient(colors: [.white.opacity(0.4), .clear, .black.opacity(0.1)], startPoint: .topLeading, endPoint: .bottomTrailing), lineWidth: 1.5)
        )
        .shadow(color: Color.black.opacity(0.15), radius: 30, x: 0, y: 20)
    }
}

struct ProtectionRow: View {
    var title: String
    var active: Bool
    var body: some View {
        HStack {
            Image(systemName: active ? "checkmark.shield.fill" : "shield.slash")
                .foregroundColor(active ? .green : .gray)
            Text(title)
                .font(.system(size: 13, weight: .medium, design: .rounded))
                .foregroundColor(.secondary)
            Spacer()
        }
    }
}

// جسر لعرض الواجهة من داخل الـ C (اختياري)
@objc(DynamicUIBridge)
public class DynamicUIBridge: NSObject {
    public static func showDashboard() {
        DispatchQueue.main.async {
            guard let windowScene = UIApplication.shared.connectedScenes.first(where: { $0.activationState == .foregroundActive }) as? UIWindowScene else {
                DispatchQueue.main.asyncAfter(deadline: .now() + 1.0) { showDashboard() }
                return
            }
            let window = UIWindow(windowScene: windowScene)
            window.windowLevel = .alert + 1
            window.backgroundColor = .clear
            window.rootViewController = UIHostingController(rootView: ProtectionDashboardView())
            window.makeKeyAndVisible()
            objc_setAssociatedObject(window, "protectionWindow", window, .OBJC_ASSOCIATION_RETAIN)
        }
    }
}
