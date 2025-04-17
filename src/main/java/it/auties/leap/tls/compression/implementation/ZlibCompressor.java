package it.auties.leap.tls.compression.implementation;

import it.auties.leap.tls.compression.TlsCompressor;

import java.nio.ByteBuffer;

public final class ZlibCompressor implements TlsCompressor {
    private static final ZlibCompressor INSTANCE = new ZlibCompressor();

    private ZlibCompressor() {

    }

    public static ZlibCompressor instance() {
        return INSTANCE;
    }

    @Override
    public void accept(ByteBuffer input, ByteBuffer output, boolean forCompression) {
        throw new UnsupportedOperationException();
    }
}
