package it.auties.leap.tls.key;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;

import static it.auties.leap.tls.TlsRecord.*;

public final class TlsRandomData {
    private static final int LENGTH = 32;

    private final byte[] data;
    private TlsRandomData(byte[] data) {
        this.data = data;
    }

    public static int length() {
        return LENGTH;
    }

    public static TlsRandomData random() {
        var data = new byte[LENGTH];
        var random = new SecureRandom();
        random.nextBytes(data);
        return new TlsRandomData(data);
    }

    public static TlsRandomData of(ByteBuffer buffer) {
        var data = readBytes(buffer, LENGTH);
        return new TlsRandomData(data);
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
        var that = (TlsRandomData) obj;
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
