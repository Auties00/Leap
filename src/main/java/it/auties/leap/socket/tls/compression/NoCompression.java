package it.auties.leap.socket.tls.compression;

import it.auties.leap.socket.tls.TlsCompression;

public final class NoCompression extends TlsCompression {
    public static final NoCompression INSTANCE = new NoCompression();

    public NoCompression() {
        super((byte) 0);
    }

    @Override
    public byte[] accept(byte[] data, int offset, int length, Mode mode) {
        return null;
    }
}
