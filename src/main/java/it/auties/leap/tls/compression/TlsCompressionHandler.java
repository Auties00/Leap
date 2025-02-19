package it.auties.leap.tls.compression;

import java.nio.ByteBuffer;

public interface TlsCompressionHandler {
    void accept(ByteBuffer input, ByteBuffer output, boolean forCompression);
}
