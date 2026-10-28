import Foundation
import Compression

/// Streaming raw DEFLATE (RFC 1951) on top of Apple's Compression framework.
final class Deflater {
    private let stream: UnsafeMutablePointer<compression_stream>
    private var buffer = [UInt8](repeating: 0, count: 256 * 1024)
    private static let dummy: UnsafeMutablePointer<UInt8> = {
        let p = UnsafeMutablePointer<UInt8>.allocate(capacity: 1); p.initialize(to: 0); return p
    }()

    init(encode: Bool) throws {
        stream = UnsafeMutablePointer<compression_stream>.allocate(capacity: 1)
        let status = compression_stream_init(stream, encode ? COMPRESSION_STREAM_ENCODE : COMPRESSION_STREAM_DECODE, COMPRESSION_ZLIB)
        guard status == COMPRESSION_STATUS_OK else { throw AXError.io("Could not start the deflate codec.") }
    }

    deinit {
        compression_stream_destroy(stream)
        stream.deallocate()
    }

    /// Feeds `input` through the codec. `ended` is true once the stream's final block was read
    /// (decoding) or fully flushed (encoding); `unused` is how many input bytes were left over.
    @discardableResult
    func process(_ input: Data, final: Bool, _ sink: (Data) throws -> Void) throws -> (ended: Bool, unused: Int) {
        var ended = false
        var unused = 0
        let flags: Int32 = final ? Int32(COMPRESSION_STREAM_FINALIZE.rawValue) : 0
        try input.withUnsafeBytes { raw in
            stream.pointee.src_ptr = raw.bindMemory(to: UInt8.self).baseAddress ?? UnsafePointer(Deflater.dummy)
            stream.pointee.src_size = input.count
            try buffer.withUnsafeMutableBufferPointer { out in
                while true {
                    stream.pointee.dst_ptr = out.baseAddress!
                    stream.pointee.dst_size = out.count
                    let status = compression_stream_process(stream, flags)
                    let produced = out.count - stream.pointee.dst_size
                    if produced > 0 { try sink(Data(bytes: out.baseAddress!, count: produced)) }
                    if status == COMPRESSION_STATUS_END { ended = true; return }
                    if status == COMPRESSION_STATUS_ERROR { throw AXError.corrupt("invalid compressed data") }
                    // END can be reported one call after the last output, so only stop once a call yields nothing.
                    if stream.pointee.src_size == 0 && stream.pointee.dst_size != 0 && produced == 0 { return }
                }
            }
        }
        unused = Int(stream.pointee.src_size)
        return (ended, unused)
    }
}
