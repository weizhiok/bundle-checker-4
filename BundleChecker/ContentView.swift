import SwiftUI
import Security
import Foundation
import Darwin
import MachO

// ========================================================================
// 🛠️ 动态链接器层 (穿透 Fishhook 的关键)
// ========================================================================

// 定义 C 函数指针类型
// 【修复 1】: 将 CFBundleRef 改为 UnsafeRawPointer，避免 Swift 类型重命名问题
typealias CFBundleGetIdFunc = @convention(c) (UnsafeRawPointer) -> CFString?

typealias SecTaskCreateFunc = @convention(c) (CFAllocator?) -> Unmanaged<AnyObject>?
typealias SecTaskCopyIdFunc = @convention(c) (AnyObject, UnsafeMutablePointer<Unmanaged<CFError>?>?) -> CFString?
typealias MethodGetImpFunc = @convention(c) (Method) -> IMP

// 核心工具：通过 dlsym 获取真实系统函数地址
func getRealFunction<T>(_ symbol: String, _ type: T.Type) -> T? {
    let RTLD_DEFAULT = UnsafeMutableRawPointer(bitPattern: -2)
    guard let addr = dlsym(RTLD_DEFAULT, symbol) else { return nil }
    return unsafeBitCast(addr, to: type)
}

// 1. dladdr 结构体
struct Local_Dl_info {
    var dli_fname: UnsafePointer<CChar>?
    var dli_fbase: UnsafeMutableRawPointer?
    var dli_sname: UnsafePointer<CChar>?
    var dli_saddr: UnsafeMutableRawPointer?
}

// ========================================================================
// 📱 主程序入口
// ========================================================================

@main
struct BundleCheckerApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}

// ========================================================================
// 🖥️ 视图与逻辑
// ========================================================================

struct ContentView: View {
    @State private var results: [ResultItem] = []
    @State private var isLoading = true
    
    // 🎯 目标 ID (你的检测通过标准)
    let targetBundleID = "com.user.bundlechecker"

    struct ResultItem: Hashable, Identifiable {
        let id = UUID()
        let method: String
        let value: String
        let detail: String
        let status: Status
    }

    enum Status {
        case safe       // 正常 (黑/绿)
        case suspicious // 异常 (红)
        case info       // 信息 (蓝)
    }

    var body: some View {
        VStack(spacing: 0) {
            Text("BundleID 破壁检测 V12")
                .font(.headline)
                .padding()
                .frame(maxWidth: .infinity)
                .background(Color(.systemGray6))
            
            if isLoading {
                VStack {
                    ProgressView()
                        .padding()
                    Text("正在穿透 Hook 层...")
                        .font(.caption)
                        .foregroundColor(.gray)
                }
                .padding()
            } else {
                List {
                    ForEach(results) { item in
                        HStack(alignment: .top) {
                            VStack(alignment: .leading, spacing: 5) {
                                Text(item.method)
                                    .font(.system(size: 14, weight: .bold))
                                    .foregroundColor(.gray)
                                
                                Text(item.value)
                                    .font(.system(size: 13, design: .monospaced))
                                    .foregroundColor(colorForStatus(item.status))
                                    .textSelection(.enabled)
                                
                                if !item.detail.isEmpty {
                                    Text(item.detail)
                                        .font(.system(size: 10))
                                        .foregroundColor(.secondary)
                                }
                            }
                        }
                        .padding(.vertical, 4)
                    }
                }
                .listStyle(.plain)
            }
        }
        .onAppear {
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) {
                performAllChecks()
                isLoading = false
            }
        }
    }

    func colorForStatus(_ status: Status) -> Color {
        switch status {
        case .safe: return .primary
        case .suspicious: return .red
        case .info: return .blue
        }
    }

    // ========================================================================
    // 🔍 核心执行逻辑
    // ========================================================================
    
    func performAllChecks() {
        var items: [ResultItem] = []
        
        // --- 1. OC API ---
        let nsID = Bundle.main.bundleIdentifier ?? "nil"
        items.append(ResultItem(
            method: "1. [OC API] Bundle.main",
            value: nsID,
            detail: "应用层 API (预期被攻破)",
            status: nsID == targetBundleID ? .safe : .suspicious
        ))
        
        // --- 2. C API (穿透 Fishhook) ---
        let cfID = getRealCFBundleID()
        items.append(ResultItem(
            method: "2. [C API] dlsym(CF...)",
            value: cfID,
            detail: "动态解析真实函数地址",
            status: cfID == targetBundleID ? .safe : .suspicious
        ))
        
        // --- 3. IO (穿透 fopen Hook) ---
        let posixID = getBundleIDUsingPosix()
        items.append(ResultItem(
            method: "3. [IO] POSIX open/read",
            value: posixID,
            detail: "系统调用直接读取 (绕过 fopen)",
            status: posixID == targetBundleID ? .safe : .suspicious
        ))
        
        // --- 4. 内核层 (穿透 SecTask Hook) ---
        let kernelID = getRealSecTaskID()
        let cleanKernelID = stripTeamID(kernelID)
        items.append(ResultItem(
            method: "4. [内核] dlsym(SecTask)",
            value: kernelID,
            detail: "动态解析内核接口",
            status: cleanKernelID == targetBundleID ? .safe : .suspicious
        ))
        
        // --- 5. 交叉验证 (授权 vs 证书) ---
        let entID = getEntitlementsAppID()
        let provID = getMobileProvisionID()
        
        let isSignatureConsistent = (provID == entID) || provID.contains(entID) || entID.contains(provID)
        let entStatus: Status = (entID.contains("Fail") || entID.contains("Found")) ? .info : (isSignatureConsistent ? .safe : .suspicious)
        let provStatus: Status = (provID.contains("未找到") || provID.contains("错误")) ? .info : (isSignatureConsistent ? .safe : .suspicious)

        items.append(ResultItem(
            method: "5. [授权] Entitlements",
            value: entID,
            detail: "App 内部权限 (穿透获取)",
            status: entStatus
        ))

        items.append(ResultItem(
            method: "6. [证书] Provisioning",
            value: provID,
            detail: "App 外部签名 (POSIX读取)",
            status: provStatus
        ))
        
        // --- 6. Runtime 完整性 (穿透 method_getImplementation 欺骗) ---
        let (rtStatus, rtMsg) = checkRealRuntimeIntegrity()
        items.append(ResultItem(
            method: "7. [Runtime] 深度反 Hook",
            value: rtStatus ? "Safe" : "Hooked!",
            detail: rtMsg,
            status: rtStatus ? .safe : .suspicious
        ))
        
        self.results = items
    }
    
    // ========================================================================
    // 🛠️ 穿透技术实现
    // ========================================================================
    
    // 2. 穿透版 CFBundle
    func getRealCFBundleID() -> String {
        // 使用 dlsym 找到真正的 CFBundleGetIdentifier
        if let realFunc = getRealFunction("CFBundleGetIdentifier", CFBundleGetIdFunc.self) {
            // 【修复 2】: 解包 Optional 的 MainBundle
            if let mainBundle = CFBundleGetMainBundle() {
                // 【修复 3】: 将 CFBundle 对象转换为 UnsafeRawPointer 传递给 C 函数
                // 这样绕过了 "CFBundle renamed to CFBundleRef" 的类型兼容性问题
                let bundlePtr = Unmanaged.passUnretained(mainBundle).toOpaque()
                
                if let cfStr = realFunc(bundlePtr) {
                    return cfStr as String
                }
            }
        }
        return "Fail (dlsym)"
    }
    
    // 3. 穿透版 IO (使用 open/read/close)
    func getBundleIDUsingPosix() -> String {
        guard let path = Bundle.main.path(forResource: "Info", ofType: "plist") else { return "No Path" }
        
        // 使用 open 系统调用
        let fd = open(path, O_RDONLY)
        if fd == -1 { return "Open Fail" }
        defer { close(fd) }
        
        let size = lseek(fd, 0, SEEK_END)
        lseek(fd, 0, SEEK_SET)
        
        if size <= 0 { return "Empty" }
        
        var buffer = [CChar](repeating: 0, count: Int(size) + 1)
        let bytesRead = read(fd, &buffer, Int(size))
        
        if bytesRead > 0 {
            let content = String(cString: buffer)
            if let range = content.range(of: "CFBundleIdentifier") {
                let sub = content[range.upperBound...]
                if let start = sub.range(of: "<string>"), let end = sub.range(of: "</string>") {
                    return String(sub[start.upperBound..<end.lowerBound])
                }
            }
        }
        return "Parse Fail"
    }
    
    // 4. 穿透版 SecTask
    func getRealSecTaskID() -> String {
        if let createFunc = getRealFunction("SecTaskCreateFromSelf", SecTaskCreateFunc.self),
           let copyFunc = getRealFunction("SecTaskCopySigningIdentifier", SecTaskCopyIdFunc.self) {
            
            if let unmanagedTask = createFunc(nil) {
                let task = unmanagedTask.takeRetainedValue()
                if let idRef = copyFunc(task, nil) {
                    return idRef as String
                }
            }
        }
        return "Fail (dlsym)"
    }
    
    // 5. 穿透版 Entitlements
    func getEntitlementsAppID() -> String {
        typealias CopyEntFunc = @convention(c) (AnyObject, CFString, UnsafeMutablePointer<Unmanaged<CFError>?>?) -> CFTypeRef?
        
        if let createFunc = getRealFunction("SecTaskCreateFromSelf", SecTaskCreateFunc.self),
           let copyEntFunc = getRealFunction("SecTaskCopyValueForEntitlement", CopyEntFunc.self) {
            
            if let unmanagedTask = createFunc(nil) {
                let task = unmanagedTask.takeRetainedValue()
                let key = "application-identifier" as CFString
                if let value = copyEntFunc(task, key, nil) as? String {
                    return stripTeamID(value)
                }
            }
        }
        return "Not Found"
    }
    
    // 6. Provisioning (POSIX)
    func getMobileProvisionID() -> String {
        guard let path = Bundle.main.path(forResource: "embedded", ofType: "mobileprovision") else {
            return "未找到"
        }
        
        let fd = open(path, O_RDONLY)
        if fd == -1 { return "Read Error" }
        defer { close(fd) }
        
        let size = lseek(fd, 0, SEEK_END)
        lseek(fd, 0, SEEK_SET)
        
        var buffer = [UInt8](repeating: 0, count: Int(size))
        read(fd, &buffer, Int(size))
        
        if let content = String(bytes: buffer, encoding: .isoLatin1) {
            if let range = content.range(of: "<key>application-identifier</key>") {
                let sub = content[range.upperBound...]
                if let start = sub.range(of: "<string>"), let end = sub.range(of: "</string>") {
                    return stripTeamID(String(sub[start.upperBound..<end.lowerBound]))
                }
            }
        }
        return "Parse Fail"
    }
    
    // 7. 真实 Runtime 检测
    func checkRealRuntimeIntegrity() -> (Bool, String) {
        let selector = #selector(getter: Bundle.bundleIdentifier)
        guard let method = class_getInstanceMethod(Bundle.self, selector) else {
            return (false, "Method Missing")
        }
        
        guard let realGetImp = getRealFunction("method_getImplementation", MethodGetImpFunc.self) else {
            return (false, "dlsym Fail")
        }
        
        let realImp = realGetImp(method)
        
        // 【修复 4】: 第二个参数类型改为 UnsafeMutableRawPointer (裸指针)
        // 避开 Swift 结构体不支持 @convention(c) 的问题
        typealias DlAddrFunc = @convention(c) (UnsafeRawPointer, UnsafeMutableRawPointer) -> Int32
        
        var info = Local_Dl_info()
        guard let dladdrPtr = dlsym(UnsafeMutableRawPointer(bitPattern: -2), "dladdr") else {
            return (false, "No dladdr")
        }
        let dladdrFunc = unsafeBitCast(dladdrPtr, to: DlAddrFunc.self)
        
        let impPtr = UnsafeRawPointer(realImp)
        // 【修复 5】: 调用时将 &info 转换为裸指针
        let infoRaw = UnsafeMutableRawPointer(&info)
        
        if dladdrFunc(impPtr, infoRaw) != 0 {
            if let fnamePtr = info.dli_fname {
                let fname = String(cString: fnamePtr)
                if fname.contains("CoreFoundation") || fname.contains("Foundation") {
                    return (true, "System Framework")
                } else {
                    let libName = URL(fileURLWithPath: fname).lastPathComponent
                    return (false, "Hooked by: \(libName)")
                }
            }
        }
        
        return (false, "Check Failed")
    }
    
    func stripTeamID(_ fullID: String) -> String {
        let components = fullID.components(separatedBy: ".")
        if components.count > 1 && components[0].count == 10 {
            let potentialTeamID = components[0]
            let charset = CharacterSet.alphanumerics
            if potentialTeamID.rangeOfCharacter(from: charset.inverted) == nil {
                return components.dropFirst().joined(separator: ".")
            }
        }
        return fullID
    }
}
