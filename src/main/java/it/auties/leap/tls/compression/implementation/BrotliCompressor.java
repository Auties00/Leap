package it.auties.leap.tls.compression.implementation;

import it.auties.leap.tls.compression.TlsCompressor;

import java.nio.ByteBuffer;

public final class BrotliCompressor implements TlsCompressor {
    private static final BrotliCompressor INSTANCE = new BrotliCompressor();

    private BrotliCompressor() {

    }

    public static BrotliCompressor instance() {
        return INSTANCE;
    }

    @Override
    public void accept(ByteBuffer input, ByteBuffer output, boolean forCompression) {
        throw new UnsupportedOperationException();
    }
}
