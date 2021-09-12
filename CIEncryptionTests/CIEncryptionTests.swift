//
//  CIEncryptionTests.swift
//  CIEncryptionTests
//
//  Created by Tharindu Madushanka on 9/13/21.
//

import XCTest
@testable import CIEncryption

class CIEncryptionTests: XCTestCase {
    
    var msg: String = "" // message to encrypt
    var encMsg: String = "" // encrypted message to decrypt
    var password: String = "En3r9pt10nK5y" //"En3r9pt10nK5y886En3r9pt1" // ex. En3r9pt10nK5y
    var aesKey: String = "" // SHA-256 hash of password
    var tdesKey: String = "En3r9pt10nK5y886En3r9pt1" // requires 24 bytes or more to be successful for des

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
        // Hash password
        aesKey = password.sha256()!
        print("AES Key:\(aesKey)")
    }

    override func tearDownWithError() throws {
        // This method is called after the invocation of each test method in the class.
    }

    func testAESEncryption() throws {
        print("Msg:\(msg) Size:\(msg.count)")
        self.measure {
            // measures AES encryption time
            let enc = msg.aesEncrypt(key: aesKey)
            print("Enc:\(enc!)")
        }
    }
    
    func testAESDecryption() throws {
        print("EncMsg:\(encMsg) Size:\(encMsg.count)")
        self.measure {
            // measures AES decryption time
            let val = encMsg.aesDecrypt(key: aesKey)
            print("Decrypted:\(val!)")
        }
    }

}
