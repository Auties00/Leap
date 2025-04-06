package it.auties.leap.tls.compressor;

import it.auties.leap.tls.compressor.implementation.*;

import java.nio.ByteBuffer;

public interface TlsCompressor {
    static TlsCompressor none() {
        return NoCompressor.instance();
    }

    static TlsCompressor deflate() {
        return DeflateCompressor.instance();
    }

    static TlsCompressor zlib() {
        return ZlibCompressor.instance();
    }

    static TlsCompressor brotli() {
        return BrotliCompressor.instance();
    }

    static TlsCompressor zstd() {
        return ZstdCompressor.instance();
    }

    void accept(ByteBuffer input, ByteBuffer output, boolean forCompression);
}
