import Foundation
import CommonCrypto
import CryptoKit

/// WinZip AE-x (AES-CTR + HMAC-SHA1) and legacy PKWARE "ZipCrypto".
enum ZipAES {
    /// key length in bytes for the WinZip strength code (1/2/3 = AES-128/192/256)
    static func keyLength(_ strength: Int) -> Int { [0, 16, 24, 32][strength] }
    static func saltLength(_ strength: Int) -> Int { [0, 8, 12, 16][strength] }

    struct Keys { var enc: Data; var auth: Data; var verifier: Data }

    static func deriveKeys(password: String, salt: Data, strength: Int) throws -> Keys {
        let kl = keyLength(strength)
        var derived = [UInt8](repeating: 0, count: 2 * kl + 2)
        let pw = Array(password.utf8)
        let status = salt.withUnsafeBytes { s in
            CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2), pw.map { Int8(bitPattern: $0) }, pw.count,
                                 s.bindMemory(to: UInt8.self).baseAddress!, salt.count,
                                 CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA1), 1000, &derived, derived.count)
        }
        guard status == kCCSuccess else { throw AXError.io("Key derivation failed.") }
        return Keys(enc: Data(derived[0..<kl]), auth: Data(derived[kl..<2 * kl]), verifier: Data(derived[2 * kl..<2 * kl + 2]))
    }

    /// AES in CTR mode with the little-endian counter WinZip uses (counter starts at 1).
    /// Built from public AES-ECB: the keystream is E(counter) for consecutive counter blocks.
    final class Cipher {
        private var cryptor: CCCryptorRef?
        private var counter: UInt64 = 1
        private var keystream = [UInt8]()
        private var position = 0

        init(key: Data) throws {
            let status = key.withUnsafeBytes { k in
                CCCryptorCreate(CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmAES), CCOptions(kCCOptionECBMode),
                                k.baseAddress, key.count, nil, &cryptor)
            }
            guard status == kCCSuccess else { throw AXError.io("Could not start AES.") }
        }
        deinit { if let c = cryptor { CCCryptorRelease(c) } }

        private func extendKeystream(by bytes: Int) throws {
            let blocks = (bytes + 15) / 16
            var input = [UInt8](repeating: 0, count: blocks * 16)
            for b in 0..<blocks {
                var c = counter
                for i in 0..<8 { input[b * 16 + i] = UInt8(truncatingIfNeeded: c); c >>= 8 }   // little-endian
                counter &+= 1
            }
            var output = [UInt8](repeating: 0, count: input.count)
            var moved = 0
            let status = CCCryptorUpdate(cryptor, input, input.count, &output, output.count, &moved)
            guard status == kCCSuccess, moved == input.count else { throw AXError.io("AES failure.") }
            keystream.removeFirst(position)
            position = 0
            keystream.append(contentsOf: output)
        }

        /// CTR is symmetric: the same call encrypts and decrypts.
        func apply(_ data: Data) throws -> Data {
            let available = keystream.count - position
            if data.count > available { try extendKeystream(by: data.count - available) }
            var out = data
            var i = out.startIndex
            for k in 0..<data.count { out[i] ^= keystream[position + k]; i += 1 }
            position += data.count
            return out
        }
    }

    final class Mac {
        private var hmac: HMAC<Insecure.SHA1>
        init(key: Data) { hmac = HMAC<Insecure.SHA1>(key: SymmetricKey(data: key)) }
        func update(_ d: Data) { hmac.update(data: d) }
        func tag() -> Data { Data(hmac.finalize().prefix(10)) }
    }
}

struct ZipCrypto {
    private var k0: UInt32 = 0x1234_5678
    private var k1: UInt32 = 0x2345_6789
    private var k2: UInt32 = 0x3456_7890

    init(password: String) { for b in password.utf8 { update(b) } }

    private mutating func update(_ b: UInt8) {
        k0 = CRC32.step(k0, b)
        k1 = (k1 &+ (k0 & 0xff)) &* 134_775_813 &+ 1
        k2 = CRC32.step(k2, UInt8(k1 >> 24))
    }

    private var streamByte: UInt8 {
        let t = (k2 | 2) & 0xffff
        return UInt8(truncatingIfNeeded: (t &* (t ^ 1)) >> 8)
    }

    mutating func decrypt(_ data: Data) -> Data {
        var out = data
        for i in out.indices { let c = out[i] ^ streamByte; update(c); out[i] = c }
        return out
    }

    mutating func encrypt(_ data: Data) -> Data {
        var out = data
        for i in out.indices { let p = out[i]; out[i] = p ^ streamByte; update(p) }
        return out
    }
}
