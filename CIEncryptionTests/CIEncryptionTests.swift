//
//  CIEncryptionTests.swift
//  CIEncryptionTests
//
//  Created by Tharindu Madushanka on 9/13/21.
//

import XCTest
import CryptoSwift
@testable import CIEncryption

class CIEncryptionTests: XCTestCase {
    
    var msg: String = "" // message to encrypt
    var encMsg: String = "" // AES encrypted message to decrypt
    var encMsg2: String = "" // DES encrypted message to decrypt
    var encMsg3: String = "" // 3DES encrypted message to decrypt
    var encMsg4: String = "" // Blowfish encrypted message to decrypt
    var password: String = "En3r9pt10nK5y" //"En3r9pt10nK5y886En3r9pt1" // ex. En3r9pt10nK5y
    var encKey: String = "" // SHA-256 hash of password
    
    override func setUpWithError() throws {
        // Load the message to encrypt from data file, called before every test
        let bundle = Bundle(for: type(of: self))
        // plaintext message
        if let path = bundle.url(forResource: "encmsg", withExtension: "txt")
        {
            msg = try! String(contentsOf: path)
        }
        // encrypted message
        if let path = bundle.url(forResource: "decmsg", withExtension: "txt")
        {
            encMsg = try! String(contentsOf: path)
        }
        if let path = bundle.url(forResource: "decmsg2", withExtension: "txt")
        {
            encMsg2 = try! String(contentsOf: path)
        }
        if let path = bundle.url(forResource: "decmsg3", withExtension: "txt")
        {
            encMsg3 = try! String(contentsOf: path)
        }
        if let path = bundle.url(forResource: "decmsg4", withExtension: "txt")
        {
            encMsg4 = try! String(contentsOf: path)
        }
        // Hash password
        encKey = password.sha256()!
        print("Encryption Key:\(encKey)")
        print("--------------------------------")
    }

    override func tearDownWithError() throws {
        // This method is called after the invocation of each test method in the class.
    }
    
    /// AES Encryption & Decryptions

    func testAESEncryption() throws {
        print("------------AES-------------")
        print("Msg:\(msg) Size:\(msg.count)")
        self.measure {
            // measures AES encryption time
            let enc = msg.aesEncrypt(key: encKey)
            print("Enc:\(enc!)")
        }
    }
    
    func testAESDecryption() throws {
        print("------------AES Decrypt-------------")
        print("EncMsg:\(encMsg) Size:\(encMsg.count)")
        self.measure {
            // measures AES decryption time
            let val = encMsg.aesDecrypt(key: encKey)
            print("Decrypted:\(val!)")
        }
    }
    
    /// DES Encryption & Decryptions
    
    func testDESEncryption() throws {
        print("------------DES-------------")
        print("Msg:\(msg) Size:\(msg.count)")
        self.measure {
            // measures DES encryption time
            let enc = msg.desEncrypt(key: encKey)
            print("Enc:\(enc!)")
        }
    }
    
    func testDESDecryption() throws {
        print("------------DES Decrypt-------------")
        print("EncMsg:\(encMsg2) Size:\(encMsg2.count)")
        self.measure {
            // measures DES decryption time
            let val = encMsg2.desDecrypt(key: encKey)
            print("Decrypted:\(val!)")
        }
    }
    
    /// DES Encryption & Decryptions
    
    func test3DESEncryption() throws {
        print("------------3DES-------------")
        print("Msg:\(msg) Size:\(msg.count)")
        self.measure {
            // measures 3DES encryption time
            let enc = msg.tripleDesEncrypt(key: encKey)
            print("Enc:\(enc!)")
        }
    }
    
    func test3DESDecryption() throws {
        print("------------3DES Decrypt-------------")
        print("EncMsg:\(encMsg3) Size:\(encMsg3.count)")
        self.measure {
            // measures 3DES decryption time
            let val = encMsg3.tripleDesDecrypt(key: encKey)
            print("Decrypted:\(val!)")
        }
    }
    
    /// Blowfish Encryption & Decryptions
    
    func testBlowfishEncryption() throws {
        print("------------Blowfish-------------")
        print("Msg:\(msg) Size:\(msg.count)")
        self.measure {
            // measures 3DES encryption time
            let bytes = try! Blowfish(key: encKey.bytes, padding: .pkcs7).encrypt(msg.bytes)
            let val = bytes.toBase64()
            print("Enc Val:\(val) Size:\(val.count)")
//            let dec = try! Blowfish(key: encKey.bytes, padding: .pkcs7).decrypt(Data(base64Encoded: val)!.bytes)
//            if let decryptedString = String(data: Data(dec), encoding: .utf8) {
//                print("DEC: \(decryptedString)")
//            } else {
//                print ("Failed!")
//            }
        }
    }
    
    func testBlowfishDecryption() throws {
        print("------------Blowfish Decrypt-------------")
        print("Msg:\(encMsg4) Size:\(encMsg4.count)")
        self.measure {
            // measures 3DES encryption time
            let val = try! Blowfish(key: encKey.bytes, padding: .pkcs7).decrypt(Data(base64Encoded: encMsg4)!.bytes)
            let decrypted = String(data: Data(val), encoding: .utf8)!
            print("Decrypted:\(decrypted)")
        }
    }

}
