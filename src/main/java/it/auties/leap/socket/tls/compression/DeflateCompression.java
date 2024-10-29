package it.auties.leap.socket.tls.compression;

import it.auties.leap.socket.tls.TlsCompression;

public final class DeflateCompression extends TlsCompression {
    public static final DeflateCompression INSTANCE = new DeflateCompression();

    private DeflateCompression() {
        super((byte) 1);
    }

    @Override
    public byte[] accept(byte[] data, int offset, int length, Mode mode) {
        return null;
    }
}
