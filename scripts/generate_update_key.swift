import CryptoKit
import Foundation

// Makes a new Ed25519 update-signing key pair. Used by setup-update-signing.sh; writes private.b64 and public.b64 (base64 of the
// 32 raw key bytes) into the folder given as the first argument.

guard CommandLine.arguments.count == 2 else { fputs("usage: generate_update_key.swift <folder>\n", stderr); exit(2) }
let dir = CommandLine.arguments[1]
let key = Curve25519.Signing.PrivateKey()
do {
    try key.rawRepresentation.base64EncodedString().write(toFile: dir + "/private.b64", atomically: true, encoding: .utf8)
    try key.publicKey.rawRepresentation.base64EncodedString().write(toFile: dir + "/public.b64", atomically: true, encoding: .utf8)
} catch {
    fputs("could not write the key files: \(error)\n", stderr); exit(1)
}
