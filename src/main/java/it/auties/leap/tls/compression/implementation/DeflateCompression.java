package it.auties.leap.tls.compression.implementation;

import it.auties.leap.tls.compression.TlsCompression;
import it.auties.leap.tls.compressor.TlsCompressor;

public final class DeflateCompression implements TlsCompression {
    private static final DeflateCompression INSTANCE = new DeflateCompression();

    private DeflateCompression() {

    }

    public static DeflateCompression instance() {
        return INSTANCE;
    }

    @Override
    public Byte id() {
        return 1;
    }

    @Override
    public TlsCompressor compressor() {
        return TlsCompressor.deflate();
    }
}
