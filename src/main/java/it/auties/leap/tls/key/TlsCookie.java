package it.auties.leap.tls.key;

import it.auties.leap.tls.config.TlsVersion;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Optional;

import static it.auties.leap.tls.util.BufferHelper.readBytesLittleEndian8;
import static it.auties.leap.tls.util.BufferHelper.writeBytesLittleEndian8;

public final class TlsCookie {
    private static final TlsCookie EMPTY = new TlsCookie(new byte[0]);

    private final byte[] data;
    private TlsCookie(byte[] data) {
        this.data = data;
    }

    public static TlsCookie empty() {
        return EMPTY;
    }

    public static Optional<TlsCookie> of(TlsVersion version, ByteBuffer buffer) {
        return switch (version.protocol()) {
            case TCP -> {
                var data = readBytesLittleEndian8(buffer);
                yield Optional.of(new TlsCookie(data));
            }
            case UDP -> Optional.empty();
        };
    }

    public void serialize(ByteBuffer buffer) {
        writeBytesLittleEndian8(buffer, data);
    }

    public byte[] data() {
        return data;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == this) return true;
        if (obj == null || obj.getClass() != this.getClass()) return false;
        var that = (TlsCookie) obj;
        return Arrays.equals(this.data, that.data);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(data);
    }

    @Override
    public String toString() {
        return "TlsCookie[" + "data=" + Arrays.toString(data) + ']';
    }

    public int length() {
        return data.length;
    }
}
