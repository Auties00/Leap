package it.auties.leap.tls.compression;

import it.auties.leap.tls.compression.implementation.DeflateCompression;
import it.auties.leap.tls.compression.implementation.NoCompression;

import java.nio.ByteBuffer;

public interface TlsCompressor {
    static TlsCompression none() {
        return NoCompression.instance();
    }

    static TlsCompression deflate() {
        return DeflateCompression.instance();
    }

    void accept(ByteBuffer input, ByteBuffer output, boolean forCompression);
}
