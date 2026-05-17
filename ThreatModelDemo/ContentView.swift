import SwiftUI
import Security
import Foundation

struct ContentView: View {
    @State private var token: String = ""
    @State private var message: String = ""
    @State private var isJailbroken: String = "?"
    
    var body: some View {
        VStack(spacing: 20) {
            Text("Threat Modeling Demo")
                .font(.title)
            
            Text("Jailbreak status: \(isJailbroken)")
                .font(.caption)
                .foregroundColor(isJailbroken == "Yes" ? .red : .green)
            
            Button("Save Token to Keychain") {
                saveToken("secret_token_123")
                message = "Token saved"
            }
            
            Button("Read Token from Keychain") {
                if let t = readToken() {
                    message = "Token: \(t)"
                } else {
                    message = "No token found"
                }
            }
            
            Button("Send API Request") {
                sendRequest()
            }
            
            Text(message)
                .padding()
        }
        .padding()
        .onAppear {
            isJailbroken = checkJailbreak() ? "Yes" : "No"
        }
    }
    
    // Вспомогательная функция для вызова C-функций stat
    func fileExistsViaStat(_ path: String) -> Bool {
        var statbuf = stat()
        return stat(path, &statbuf) == 0
    }

    func checkJailbreak() -> Bool {
        // 1. Проверка файлов через stat (более низкоуровневая, чем FileManager)
        let paths = [
            "/Applications/Cydia.app",
            "/Library/MobileSubstrate/MobileSubstrate.dylib",
            "/usr/sbin/sshd",
            "/etc/apt",
            "/var/jb",
            "/usr/sbin/frida-server",
            "/bin/bash",
            "/usr/bin/ssh",
            "/usr/lib/TweakInject",
            "/Applications/Sileo.app"
        ]
        for path in paths {
            if fileExistsViaStat(path) {
                print("[JB] File found via stat: \(path)")
                return true
            }
        }
        
        // 2. Проверка URL-схем
        let urls = ["cydia://", "sileo://", "zbra://"]
        for url in urls {
            if UIApplication.shared.canOpenURL(URL(string: url)!) {
                print("[JB] URL scheme accessible: \(url)")
                return true
            }
        }
        
        // 3. Проверка возможности записи в /var/tmp
        let testPath = "/private/var/tmp/jb_test.txt"
        do {
            try "test".write(toFile: testPath, atomically: true, encoding: .utf8)
            try FileManager.default.removeItem(atPath: testPath)
            print("[JB] Write access to /private/var/tmp")
            return true
        } catch {}
        
        // 4. Проверка через access() C-функцию
        let extraPaths = ["/var/checkra1n.dmg", "/var/binpack", "/.bootstrapped_electra"]
        for path in extraPaths {
            if access(path, F_OK) == 0 {
                print("[JB] File found via access: \(path)")
                return true
            }
        }
        
        return false
    }
    
    func saveToken(_ token: String) {
        let data = token.data(using: .utf8)!
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: "user_token",
            kSecValueData as String: data
        ]
        SecItemAdd(query as CFDictionary, nil)
    }
    
    func readToken() -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: "user_token",
            kSecReturnData as String: true
        ]
        var result: CFTypeRef?
        SecItemCopyMatching(query as CFDictionary, &result)
        guard let data = result as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }
    
    func sendRequest() {
        guard let url = URL(string: "https://httpbin.org/get?token=\(readToken() ?? "none")") else {
            message = "Invalid URL"
            return
        }
        
        let session = URLSession(configuration: .default, delegate: PinningDelegate(), delegateQueue: nil)
        session.dataTask(with: url) { data, _, error in
            DispatchQueue.main.async {
                if let error = error {
                    message = "Error: \(error.localizedDescription)"
                } else if let data = data {
                    message = "Response: \(String(data: data, encoding: .utf8)?.prefix(100) ?? "")..."
                }
            }
        }.resume()
    }
}

class PinningDelegate: NSObject, URLSessionDelegate {
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        guard let serverTrust = challenge.protectionSpace.serverTrust,
              let certificate = SecTrustGetCertificateAtIndex(serverTrust, 0) else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        
        let serverCertData = SecCertificateCopyData(certificate) as Data
        let pinnedCertData = pinnedCertificateData()
        
        if serverCertData == pinnedCertData {
            completionHandler(.useCredential, URLCredential(trust: serverTrust))
        } else {
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }
    
    func pinnedCertificateData() -> Data {
        let pinnedCertString = """
        -----BEGIN CERTIFICATE-----
        MIIDdzCCAl+gAwIBAgIEAgAAuTANBgkqhkiG9w0BAQsFADBsMRAwDgYDVQQGEwdV
        bmtub3duMRAwDgYDVQQIEwdVbmtub3duMRAwDgYDVQQHEwdVbmtub3duMRAwDgYD
        VQQKEwdVbmtub3duMRAwDgYDVQQLEwdVbmtub3duMRAwDgYDVQQDEwdodHRwYmlu
        MB4XDTI0MDQxOTEwMDAwMFoXDTI0MDQyMDEwMDAwMFowbDEQMA4GA1UEBhMHVW5r
        bm93bjEQMA4GA1UECBMHVW5rbm93bjEQMA4GA1UEBxMHVW5rbm93bjEQMA4GA1UE
        ChMHVW5rbm93bjEQMA4GA1UECxMHVW5rbm93bjEQMA4GA1UEAxMHaHR0cGJpbjCC
        ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALu2NSD/3kOjzGkG9+wZf1O/
        kLpLq0q8NnBvG8wL6qJjq6yQGjR0/8Rg6nQ0rLjRZjZc0fXhWqK5f5Xy8YcL5qW0
        ...
        -----END CERTIFICATE-----
        """
        return Data(pinnedCertString.utf8)
    }
}

#Preview {
    ContentView()
}
