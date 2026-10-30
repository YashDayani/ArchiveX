import Foundation

/// The public half of the key that release zips are signed with (Ed25519). The updater only installs a zip whose
/// `ArchiveX.zip.sig` verifies against this key, so a stolen GitHub account cannot ship a malicious update.
///
/// `scripts/setup-update-signing.sh` fills this in once. Until then it is empty, the updater skips the signature check,
/// and the release workflow refuses to publish.
enum UpdateKey {
    static let publicKeyBase64 = ""

    /// The 32 raw key bytes, or nil while signing is not set up.
    static var publicKey: Data? {
        guard let d = Data(base64Encoded: publicKeyBase64), d.count == 32 else { return nil }
        return d
    }
}
