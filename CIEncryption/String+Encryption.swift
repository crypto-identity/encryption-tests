import Foundation
import CommonCrypto
import Security

/// Extension for Symmetric Encryption and Decryption with DES, 3DES, AES algorithms
extension String {
    
    /// Encrypts message with DES algorithm
    func desEncrypt(key:String) -> String? {
        
        return symetricEncrypt(key: key, blockSize: kCCBlockSizeDES, keyLength: size_t(kCCKeySizeDES), algorithm: UInt32(kCCAlgorithmDES))
    }
    
    /// Encrypts message with 3DES algorithm
    func tripleDesEncrypt(key:String) -> String? {
        
        return symetricEncrypt(key: key, blockSize: kCCBlockSize3DES, keyLength: size_t(kCCKeySize3DES), algorithm: UInt32(kCCAlgorithm3DES))
    }
    
    /// Encrypts message with AES 128 algorithm
    func aes128Encrypt(key:String) -> String? {
        
        return symetricEncrypt(key: key, blockSize: kCCBlockSizeAES128, keyLength: size_t(kCCKeySizeAES128), algorithm: UInt32(kCCAlgorithmAES128))
    }
    
    /// Encrypts message with AES algorithm with 256 key length
    func aesEncrypt(key:String) -> String? {
        
        return symetricEncrypt(key: key, blockSize: kCCBlockSizeAES128, keyLength: size_t(kCCKeySizeAES256), algorithm: UInt32(kCCAlgorithmAES))
    }
    
    /// Encrypts a message with symmetric algorithm
    func symetricEncrypt(key:String, blockSize: Int, keyLength: size_t, algorithm: CCAlgorithm, options: Int = kCCOptionPKCS7Padding) -> String? {
        let keyData = key.data(using: String.Encoding.utf8)! as NSData
        let data = self.data(using: String.Encoding.utf8)! as NSData
        
        let cryptData = NSMutableData(length: Int(data.length) + blockSize)!

        let operation: CCOperation = UInt32(kCCEncrypt)

        var numBytesEncrypted :size_t = 0

        let cryptStatus = CCCrypt(operation,
                                  algorithm,
                                  UInt32(options),
                                  keyData.bytes, keyLength,
                                  nil,
                                  data.bytes, data.length,
                                  cryptData.mutableBytes, cryptData.length,
                                  &numBytesEncrypted)
        
        if UInt32(cryptStatus) == UInt32(kCCSuccess) {
            cryptData.length = Int(numBytesEncrypted)
            let base64cryptString = cryptData.base64EncodedString(options: .lineLength64Characters)
            return base64cryptString
        }
        else {
            return nil
        }
    }
    
    /// Decrypts message with DES algorithm
    func desDecrypt(key:String) -> String? {
        
        return symetricDecrypt(key: key, blockSize: kCCBlockSizeDES, keyLength: size_t(kCCKeySizeDES), algorithm: UInt32(kCCAlgorithmDES))
    }
    
    /// Decrypts message with 3DES algorithm
    func tripleDesDecrypt(key:String) -> String? {
        
        return symetricDecrypt(key: key, blockSize: kCCBlockSize3DES, keyLength: size_t(kCCKeySize3DES), algorithm: UInt32(kCCAlgorithm3DES))
    }
    
    /// Decrypts message with AES 128 algorithm
    func aes128Decrypt(key:String) -> String? {
        
        return symetricDecrypt(key: key, blockSize: kCCBlockSizeAES128, keyLength: size_t(kCCKeySizeAES128), algorithm: UInt32(kCCAlgorithmAES128))
    }
    
    /// Decrypts message with AES algorithm with 256 key length
    func aesDecrypt(key:String) -> String? {
        
        return symetricDecrypt(key: key, blockSize: kCCBlockSizeAES128, keyLength: size_t(kCCKeySizeAES256), algorithm: UInt32(kCCAlgorithmAES))
    }

    /// Decrypts a message with symmetric algorithm
    func symetricDecrypt(key:String, blockSize: Int, keyLength: size_t, algorithm: CCAlgorithm, options: Int = kCCOptionPKCS7Padding) -> String? {
        if let keyData = key.data(using: String.Encoding.utf8),
            let data = NSData(base64Encoded: self, options: .ignoreUnknownCharacters),
            let cryptData    = NSMutableData(length: Int((data.length)) + blockSize) {

            let operation: CCOperation = UInt32(kCCDecrypt)
            var numBytesEncrypted :size_t = 0

            let cryptStatus = CCCrypt(operation,
                                      algorithm,
                                      UInt32(options),
                                      (keyData as NSData).bytes, keyLength,
                                      nil,
                                      data.bytes, data.length,
                                      cryptData.mutableBytes, cryptData.length,
                                      &numBytesEncrypted)

            if UInt32(cryptStatus) == UInt32(kCCSuccess) {
                cryptData.length = Int(numBytesEncrypted)
                let unencryptedMessage = String(data: cryptData as Data, encoding:String.Encoding.utf8)
                return unencryptedMessage
            }
            else {
                return nil
            }
        }
        return nil
    }
    
    func sha256(_ data: Data) -> Data? {
        guard let res = NSMutableData(length: Int(CC_SHA256_DIGEST_LENGTH)) else { return nil }
        CC_SHA256((data as NSData).bytes, CC_LONG(data.count), res.mutableBytes.assumingMemoryBound(to: UInt8.self))
        return res as Data
    }
    
    func sha1(_ data: Data) -> Data? {
        guard let res = NSMutableData(length: Int(CC_SHA1_DIGEST_LENGTH)) else { return nil }
        CC_SHA1((data as NSData).bytes, CC_LONG(data.count), res.mutableBytes.assumingMemoryBound(to: UInt8.self))
        return res as Data
    }

    func sha256() -> String? {
        guard
            let data = self.data(using: String.Encoding.utf8),
            let shaData = sha256(data)
            else { return nil }
        let rc = shaData.base64EncodedString(options: [])
        return rc
    }
    
    func sha1() -> String? {
        guard
            let data = self.data(using: String.Encoding.utf8),
            let shaData = sha256(data)
            else { return nil }
        let rc = shaData.base64EncodedString(options: [])
        return rc
    }
    
}
