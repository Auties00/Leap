package it.auties.leap.tls.compression;

import it.auties.leap.tls.TlsCompression;

public final class NoCompression extends TlsCompression {
    public static final NoCompression INSTANCE = new NoCompression();
    public static final byte ID = (byte) 0;

    public NoCompression() {
        super(ID);
    }

    @Override
    public byte[] accept(byte[] data, int offset, int length, Mode mode) {
        return null;
    }
}
