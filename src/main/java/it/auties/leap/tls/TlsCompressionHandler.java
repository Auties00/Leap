package it.auties.leap.tls;

import java.nio.ByteBuffer;

@FunctionalInterface
public interface TlsCompressionHandler {
    void accept(ByteBuffer input, ByteBuffer output, boolean forCompression);
}