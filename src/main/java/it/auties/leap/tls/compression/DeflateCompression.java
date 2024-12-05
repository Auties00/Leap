package it.auties.leap.tls.compression;

import it.auties.leap.tls.TlsCompression;

public final class DeflateCompression extends TlsCompression {
    public static final DeflateCompression INSTANCE = new DeflateCompression();
    public static final byte ID = (byte) 1;

    private DeflateCompression() {
        super(ID);
    }

    @Override
    public byte[] accept(byte[] data, int offset, int length, Mode mode) {
        return null;
    }
}
