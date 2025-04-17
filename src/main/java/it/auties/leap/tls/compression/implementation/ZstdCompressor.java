package it.auties.leap.tls.compression.implementation;

import it.auties.leap.tls.compression.TlsCompressor;

import java.nio.ByteBuffer;

public final class ZstdCompressor implements TlsCompressor {
    private static final ZstdCompressor INSTANCE = new ZstdCompressor();

    private ZstdCompressor() {

    }

    public static ZstdCompressor instance() {
        return INSTANCE;
    }

    @Override
    public void accept(ByteBuffer input, ByteBuffer output, boolean forCompression) {
        throw new UnsupportedOperationException();
    }
}
