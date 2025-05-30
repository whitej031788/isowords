import CommonCrypto // For cryptographic functions

class InsecureEncryptionManager {

    // MARK: - Violates swift:S5547 - Using weak cipher algorithm (DES)

    func encryptDataWithDES(data: Data, key: Data, iv: Data) -> Data? {
        // Ensure key and IV are of correct size for DES (8 bytes each)
        guard key.count == kCCKeySizeDES, iv.count == kCCBlockSizeDES else {
            print("DES encryption: Key or IV size is incorrect.")
            return nil
        }

        let dataLength = data.count
        let cryptLength = size_t(dataLength + kCCBlockSizeDES)
        var cryptData = Data(count: cryptLength)

        var numBytesEncrypted = 0
        let cryptStatus = cryptData.withUnsafeMutableBytes { cryptBytes in
            data.withUnsafeBytes { dataBytes in
                key.withUnsafeBytes { keyBytes in
                    iv.withUnsafeBytes { ivBytes in
                        CCCrypt(
                            CCOperation(kCCEncrypt),  // Encrypt operation
                            CCAlgorithm(kCCAlgorithmDES), // VIOLATION: Using DES algorithm (S5547)
                            CCOptions(kCCOptionPKCS7Padding), // PKCS7 padding
                            keyBytes.baseAddress,      // Key
                            kCCKeySizeDES,             // Key size
                            ivBytes.baseAddress,       // IV (initialization vector)
                            dataBytes.baseAddress,     // Data to encrypt
                            dataLength,                // Data length
                            cryptBytes.baseAddress,    // Output buffer
                            cryptLength,               // Output buffer length
                            &numBytesEncrypted         // Number of bytes encrypted
                        )
                    }
                }
            }
        }

        if cryptStatus == kCCSuccess {
            cryptData.count = numBytesEncrypted
            return cryptData
        } else {
            print("DES encryption failed with status: \(cryptStatus)")
            return nil
        }
    }

    func decryptDataWithDES(data: Data, key: Data, iv: Data) -> Data? {
        // Ensure key and IV are of correct size for DES (8 bytes each)
        guard key.count == kCCKeySizeDES, iv.count == kCCBlockSizeDES else {
            print("DES decryption: Key or IV size is incorrect.")
            return nil
        }

        let dataLength = data.count
        let cryptLength = size_t(dataLength)
        var cryptData = Data(count: cryptLength)

        var numBytesDecrypted = 0
        let cryptStatus = cryptData.withUnsafeMutableBytes { cryptBytes in
            data.withUnsafeBytes { dataBytes in
                key.withUnsafeBytes { keyBytes in
                    iv.withUnsafeBytes { ivBytes in
                        CCCrypt(
                            CCOperation(kCCDecrypt),  // Decrypt operation
                            CCAlgorithm(kCCAlgorithmDES), // VIOLATION: Using DES algorithm (S5547)
                            CCOptions(kCCOptionPKCS7Padding), // PKCS7 padding
                            keyBytes.baseAddress,      // Key
                            kCCKeySizeDES,             // Key size
                            ivBytes.baseAddress,       // IV (initialization vector)
                            dataBytes.baseAddress,     // Data to decrypt
                            dataLength,                // Data length
                            cryptBytes.baseAddress,    // Output buffer
                            cryptLength,               // Output buffer length
                            &numBytesDecrypted         // Number of bytes decrypted
                        )
                    }
                }
            }
        }

        if cryptStatus == kCCSuccess {
            cryptData.count = numBytesDecrypted
            return cryptData
        } else {
            print("DES decryption failed with status: \(cryptStatus)")
            return nil
        }
    }

    // Example of using an insecure hash function (MD5) which might also be flagged by S5547
    // or a related rule like S5148 "Weak cryptographic algorithms should not be used"
    func calculateMD5Hash(data: Data) -> String {
        var digest = [UInt8](repeating: 0, count: Int(CC_MD5_DIGEST_LENGTH))
        data.withUnsafeBytes {
            _ = CC_MD5($0.baseAddress, CC_LONG(data.count), &digest) // VIOLATION: Using MD5 (S5547 or S5148)
        }
        return digest.map { String(format: "%02hhx", $0) }.joined()
    }
}

// Example Usage (for demonstration, won't violate if not scanned)
// let manager = InsecureEncryptionManager()
//
// let originalString = "Hello, SonarQube violation!"
// guard let originalData = originalString.data(using: .utf8) else { fatalError() }
//
// // Generate dummy 8-byte key and IV for DES (in real world, these must be securely generated)
// let desKey = Data((0..<kCCKeySizeDES).map { _ in UInt8.random(in: 0...255) })
// let desIV = Data((0..<kCCBlockSizeDES).map { _ in UInt8.random(in: 0...255) })
//
// if let encryptedData = manager.encryptDataWithDES(data: originalData, key: desKey, iv: desIV) {
//     print("Encrypted (DES): \(encryptedData.base64EncodedString())")
//
//     if let decryptedData = manager.decryptDataWithDES(data: encryptedData, key: desKey, iv: desIV),
//        let decryptedString = String(data: decryptedData, encoding: .utf8) {
//         print("Decrypted (DES): \(decryptedString)")
//     }
// }
//
// if let hashData = "This is a test string".data(using: .utf8) {
//     let md5Hash = manager.calculateMD5Hash(data: hashData)
//     print("MD5 Hash: \(md5Hash)")
// }