package it.auties.leap.tls.compression.implementation;

import it.auties.leap.tls.compression.TlsCompression;

import java.nio.ByteBuffer;

public final class NoCompression implements TlsCompression {
    private static final NoCompression INSTANCE = new NoCompression();

    private NoCompression() {

    }

    public static NoCompression instance() {
        return INSTANCE;
    }

    @Override
    public byte id() {
        return 0;
    }

    @Override
    public void accept(ByteBuffer input, ByteBuffer output, boolean forCompression) {
        output.put(input);
    }
}
