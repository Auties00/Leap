package it.auties.leap.tls.random;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;

import static it.auties.leap.tls.util.BufferUtils.*;

public final class TlsClientRandom {
    private static final int LENGTH = 32;

    private final byte[] data;
    private TlsClientRandom(byte[] data) {
        this.data = data;
    }

    public static int length() {
        return LENGTH;
    }

    public static TlsClientRandom random() {
        var data = new byte[LENGTH];
        var random = new SecureRandom();
        random.nextBytes(data);
        return new TlsClientRandom(data);
    }

    public static TlsClientRandom of(ByteBuffer buffer) {
        var data = readBytes(buffer, LENGTH);
        return new TlsClientRandom(data);
    }

    public void serialize(ByteBuffer buffer) {
        writeBytes(buffer, data);
    }

    public byte[] data() {
        return data;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == this) return true;
        if (obj == null || obj.getClass() != this.getClass()) return false;
        var that = (TlsClientRandom) obj;
        return Arrays.equals(this.data, that.data);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(data);
    }

    @Override
    public String toString() {
        return "TlsRandomData[" + "data=" + Arrays.toString(data) + ']';
    }

}
