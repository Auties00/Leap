package it.auties.leap.tls;

import it.auties.leap.tls.compression.DeflateCompression;
import it.auties.leap.tls.compression.NoCompression;

import java.util.Optional;

public abstract class TlsCompression {
    public static Optional<TlsCompression> of(byte id) {
        return switch (id) {
            case NoCompression.ID -> Optional.of(none());
            case DeflateCompression.ID -> Optional.of(deflate());
            default -> Optional.empty();
        };
    }

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
