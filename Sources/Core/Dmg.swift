import Foundation
final class DmgArchive: ContainerArchive {
    let items: [ContainerItem] = []
    let details = "DMG"
    init(url: URL) throws { throw AXError.unsupported("disk images") }
    func stream(_ i: Int) throws -> ByteSource { throw AXError.unsupported("disk images") }
}
