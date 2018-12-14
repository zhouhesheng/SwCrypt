import UIKit
import SwCrypt

class ViewController: UIViewController {
    
    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view, typically from a nib.
        
        let aesKey = "passwordpasswordpasswordpassword".data(using: .utf8)!
        let bytes = [UInt8](repeating: 0, count: 12)
        let iv = Data(bytes: bytes)
        let testData = "source - aes256gcm".data(using: String.Encoding.utf8)!
        
        let e = try? CC.cryptAuth(.encrypt, blockMode: .gcm, algorithm: .aes, data: testData, aData: Data(), key: aesKey, iv: iv, tagLength: 16)
        let d = try? CC.cryptAuth(.decrypt, blockMode: .gcm, algorithm: .aes, data: e!, aData: Data(), key: aesKey, iv: iv, tagLength: 16)
        NSLog("e=\(e!.hexString()), d=\(d!.hexString())")
        
        
        let tagSize = 16
        let skey = try! Data(hex: "3b479df68f7fb8e75f4761e547f9b7d98467534c2c25d7b3dceec198984d43aa")
        let nonce = try! Data(hex: "030000000000000000000000")
        
        let plaintext = try! Data(hex: "170303011b652385cb999f93dfdd38e0fa1287b5cd4fabf3006aaaad1ca4a534d9d9b3bca0ec992d7f2b1a00023d8291dc4c12a99d256888147d197b6d3fd4bb52cd64fd9848938bd04781159d147f6b4e4afb5fbb7160cef2b73b99730e42cb9a20e37673b82095a2438e70f3f886cca351202b815da145f3b6ec984965e2001f860f19a537a41f9a3e8e03e976591902d713879a7563f4fcd90e6f357cb7b0cfafc231a5fcdafb317712c1b74aebec42ab36044e02f10b43dc78ec5d2dfac5d79ec85831a694c6b7b0dd4e75efb0654c8aea10c3bf30f8c5cd9b977dd468b1359b8d8a0fd624b0736fbaf1f2c8aa840953d60ef35fb93297c6839a2d9380f4b9e5e1c242a7de0c97a216d59458d1db0de2b8025dd0e0ff8e55bb0f457bbd67")
        
        let payload = try! Data(hex: "754514982ae063d7e7ab03f6400bdab8ff2d944480d0e2758736c08f6487b67af616e3c505f8743aede6194002b7cef2e847e40a69ba51dae07aab7c7f029e47a8beaeb534afdd39a31475ad143cdd0fe9f9f7e2cb42d8d1c8f5cd392e6f7ab0947419cf5372b1773896c757a77a03dc1cc33ff2f6e359c52f9ca9d395f03a49667214a77922aa13262a14dee9512be33868402fe3d281304d00f2248d649d33c0f8e4f233d3715087db8bbc5bf8fb674dcfee2c3c443c913fd238ae2fce0866a95da613e41fbcab2b142ee6fd8439809922f29f2fa26cf12796aa6646f5ce41271b31dbefaaa4f4a462d776fa9a5010e282fc6aa1694beb0ed0491e30b271f73fc5eda8de637df6755b61665b88bc98a012143eff93c736ba9f5f802a4336a0c9d5285aaed020a9c678dad41cf58c56")
        
        let en = try? CC.cryptAuth(.encrypt, blockMode: .gcm, algorithm: .aes, data: plaintext, aData: Data(), key: skey, iv: nonce, tagLength: tagSize)
        NSLog("en=\(en!.hexString()),  EQUALS=\(en==payload)")
    }
    
    override func didReceiveMemoryWarning() {
        super.didReceiveMemoryWarning()
        // Dispose of any resources that can be recreated.
    }
    
    
}



public extension Data {
    
    func withUnsafeRawPointer<ResultType>(_ body: (UnsafeRawPointer) throws -> ResultType) rethrows -> ResultType {
        return try self.withUnsafeBytes { (ptr: UnsafePointer<Int8>) -> ResultType in
            let rawPtr = UnsafeRawPointer(ptr)
            return try body(rawPtr)
        }
    }
    
    enum DataDecodingError: Error {
        case oddStringLength(Int)
    }
    
    init(hex: String) throws {
        if hex.utf8.count % 2 == 1 {
            throw DataDecodingError.oddStringLength(hex.utf8.count)
        }
        let bytes = stride(from: 0, to: hex.utf8.count, by: 2)
            .map { hex.utf8.index(hex.utf8.startIndex, offsetBy: $0) }
            .map { hex.utf8[$0...hex.utf8.index(after: $0)] }
            .map { UInt8(String($0)!, radix: 16)! }
        self.init(bytes: bytes)
    }
    
    func hexString(withSpace:Bool = false, breakAt:Int = 0) -> String {
        var bytes = [UInt8](repeating: 0, count: self.count)
        self.copyBytes(to: &bytes, count: self.count)
        var idx = 0
        var hexString = ""
        
        if breakAt > 0 {
            hexString += "\n"
        }
        
        for byte in bytes {
            hexString += String(format:"%02x", UInt8(byte))
            if withSpace {
                hexString += " "
            }
            
            if breakAt > 0 {
                idx = idx + 1
                if idx % breakAt == 0 {
                    hexString += "\n"
                }
            }
        }
        
        return hexString
    }
}
