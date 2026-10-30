import CryptoKit
import Foundation

// Signs a release file with the update key and writes <file>.sig (base64 of the 64-byte Ed25519 signature).
//   UPDATE_SIGNING_KEY   base64 of the private key (a GitHub secret)
//   UPDATE_PUBLIC_KEY    base64 of the public key built into the app (Sources/UpdateKey.swift)
// The two must belong together: a release signed with a key the app does not know would be refused by every user's updater.

guard CommandLine.arguments.count == 2 else { fputs("usage: sign_update.swift <file>\n", stderr); exit(2) }
let env = ProcessInfo.processInfo.environment
func fail(_ message: String) -> Never { fputs("error: \(message)\n", stderr); exit(1) }

guard let privateText = env["UPDATE_SIGNING_KEY"]?.trimmingCharacters(in: .whitespacesAndNewlines), !privateText.isEmpty,
      let privateRaw = Data(base64Encoded: privateText), let key = try? Curve25519.Signing.PrivateKey(rawRepresentation: privateRaw)
else { fail("UPDATE_SIGNING_KEY is missing or not a valid key. Run scripts/setup-update-signing.sh once.") }

guard let publicText = env["UPDATE_PUBLIC_KEY"]?.trimmingCharacters(in: .whitespacesAndNewlines), let publicRaw = Data(base64Encoded: publicText),
      key.publicKey.rawRepresentation == publicRaw
else { fail("the signing key does not match the public key built into the app (Sources/UpdateKey.swift).") }

let file = CommandLine.arguments[1]
guard let data = try? Data(contentsOf: URL(fileURLWithPath: file), options: .mappedIfSafe) else { fail("cannot read \(file)") }
guard let signature = try? key.signature(for: data), key.publicKey.isValidSignature(signature, for: data) else { fail("signing failed") }
do { try signature.base64EncodedString().write(toFile: file + ".sig", atomically: true, encoding: .utf8) }
catch { fail("cannot write \(file).sig") }
print("Signed \(file) -> \(file).sig")
