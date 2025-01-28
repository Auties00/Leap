package it.auties.leap.tls.key;

import it.auties.leap.tls.exception.TlsException;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;

import static it.auties.leap.tls.util.BufferUtils.readBytesLittleEndian8;
import static it.auties.leap.tls.util.BufferUtils.writeBytesLittleEndian8;

public final class TlsSharedSecret {
    private static final int LENGTH = 32;

    private final byte[] data;
    private TlsSharedSecret(byte[] data) {
        this.data = data;
    }

    public static int length() {
        return LENGTH;
    }

    public static TlsSharedSecret random() {
        var data = new byte[LENGTH];
        var random = new SecureRandom();
        random.nextBytes(data);
        return new TlsSharedSecret(data);
    }

    public static TlsSharedSecret of(ByteBuffer buffer) {
        var data = readBytesLittleEndian8(buffer);
        if (data.length != LENGTH) {
            throw new TlsException("Expected shared secret to have length " + LENGTH);
        }
        return new TlsSharedSecret(data);
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
        var that = (TlsSharedSecret) obj;
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
