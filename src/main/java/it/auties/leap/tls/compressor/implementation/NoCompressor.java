package it.auties.leap.tls.compressor.implementation;

import it.auties.leap.tls.compressor.TlsCompressor;

import java.nio.ByteBuffer;

public final class NoCompressor implements TlsCompressor {
    private static final NoCompressor INSTANCE = new NoCompressor();

    private NoCompressor() {

    }

    public static NoCompressor instance() {
        return INSTANCE;
    }

    @Override
    public void accept(ByteBuffer input, ByteBuffer output, boolean forCompression) {
        output.put(input);
    }
}
