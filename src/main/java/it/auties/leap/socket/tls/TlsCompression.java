package it.auties.leap.socket.tls;

import it.auties.leap.socket.tls.compression.DeflateCompression;
import it.auties.leap.socket.tls.compression.NoCompression;

public abstract class TlsCompression {
    private final byte id;
    protected TlsCompression(byte id) {
        this.id = id;
    }

    public static TlsCompression none() {
        return NoCompression.INSTANCE;
    }

    public static TlsCompression deflate() {
        return DeflateCompression.INSTANCE;
    }

    public abstract byte[] accept(byte[] data, int offset, int length, Mode mode);

    public byte id() {
        return id;
    }

    public enum Mode {
        COMPRESS,
        DECOMPRESS
    }
}
