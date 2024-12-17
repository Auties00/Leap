package it.auties.leap.tls.hash;

import java.nio.ByteBuffer;

public interface TlsHash {
    void update(byte input);

    void update(ByteBuffer input);

    void update(byte[] input, int offset, int len);

    int digest(byte[] output, int offset, int length, boolean reset);

    void reset();

    TlsHashType type();

    default void update(byte[] input) {
        update(input, 0, input.length);
    }

    default byte[] digest(boolean reset) {
        var length = type().length();
        var result = new byte[length];
        digest(result, 0, length, reset);
        return result;
    }

    default int digest(byte[] output, int offset, boolean reset) {
        return digest(output, offset, type().length(), reset);
    }

    default int digest(byte[] output, boolean reset) {
        return digest(output, 0, type().length(), reset);
    }

    default byte[] digest(boolean reset, int offset, int length) {
        var result = new byte[length];
        digest(result, offset, length, reset);
        return result;
    }
}
