package it.auties.leap.tls.compression;

import it.auties.leap.tls.compression.implementation.UnsupportedCompressionHandler;

import java.nio.ByteBuffer;

public interface TlsCompressionHandler {
    void accept(ByteBuffer input, ByteBuffer output, boolean forCompression);

    static TlsCompressionHandler unsupported() {
        return UnsupportedCompressionHandler.instance();
    }
}
