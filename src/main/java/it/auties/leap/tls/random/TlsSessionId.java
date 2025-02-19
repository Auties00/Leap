package it.auties.leap.tls.random;

import it.auties.leap.tls.exception.TlsException;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;

import static it.auties.leap.tls.util.BufferUtils.*;

public final class TlsSessionId {
    private static final int LENGTH = 32;

    private final byte[] data;
    private TlsSessionId(byte[] data) {
        this.data = data;
    }

    public static int length() {
        return LENGTH;
    }

    public static TlsSessionId random() {
        var data = new byte[LENGTH];
        var random = new SecureRandom();
        random.nextBytes(data);
        return new TlsSessionId(data);
    }

    public static TlsSessionId of(ByteBuffer buffer) {
        var data = readBytesBigEndian8(buffer);
        if (data.length != LENGTH) {
            throw new TlsException("Expected shared secret to have length " + LENGTH);
        }
        return new TlsSessionId(data);
    }

    public void serialize(ByteBuffer buffer) {
        writeBytesBigEndian8(buffer, data);
    }

    public byte[] data() {
        return data;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == this) return true;
        if (obj == null || obj.getClass() != this.getClass()) return false;
        var that = (TlsSessionId) obj;
        return Arrays.equals(this.data, that.data);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(data);
    }

    @Override
    public String toString() {
        return "TlsSharedSecret[" + "data=" + Arrays.toString(data) + ']';
    }
}
