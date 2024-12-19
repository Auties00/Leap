package it.auties.leap.tls.hash;

import java.nio.ByteBuffer;

public interface TlsHash {
    static TlsHash none() {
        return NoneHash.INSTANCE;
    }

    static TlsHash md5() {
        return new MD5Hash();
    }

    static TlsHash sha1() {
        return new SHA1Hash();
    }

    static TlsHash sha256() {
        return new SHA256Hash();
    }

    static TlsHash sha384() {
        return new SHA384Hash();
    }

    static TlsHash sm3() {
        return new SM3Hash();
    }

    static TlsHash gostr256() {
        return new GOSTR256Hash();
    }
    
    void update(byte input);

    void update(ByteBuffer input);

    void update(byte[] input, int offset, int len);

    int digest(byte[] output, int offset, int length, boolean reset);

    void reset();

    int length();

    int blockLength();

    default void update(byte[] input) {
        update(input, 0, input.length);
    }

    default byte[] digest(boolean reset) {
        var length = length();
        var result = new byte[length];
        digest(result, 0, length, reset);
        return result;
    }

    default int digest(byte[] output, int offset, boolean reset) {
        return digest(output, offset, length(), reset);
    }

    default int digest(byte[] output, boolean reset) {
        return digest(output, 0, length(), reset);
    }

    default byte[] digest(boolean reset, int offset, int length) {
        var result = new byte[length];
        digest(result, offset, length, reset);
        return result;
    }
}
