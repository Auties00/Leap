package it.auties.leap.tls.compression.implementation;

import it.auties.leap.tls.compression.TlsCompression;
import it.auties.leap.tls.compressor.TlsCompressor;

public final class NoCompression implements TlsCompression {
    private static final NoCompression INSTANCE = new NoCompression();

    private NoCompression() {

    }

    public static NoCompression instance() {
        return INSTANCE;
    }

    @Override
    public Byte id() {
        return 0;
    }

    @Override
    public TlsCompressor compressor() {
        return TlsCompressor.none();
    }
}
