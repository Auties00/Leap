package it.auties.leap.tls.hash;

import it.auties.leap.tls.TlsHashType;
import it.auties.leap.tls.hash.digest.*;

import java.nio.ByteBuffer;

public sealed abstract class TlsHash permits GOSTR_3411_2012_256, MD5, NULL, SHA1, SHA256, SHA384, SM3 {
    public static TlsHash of(TlsHashType hashType) {
        return switch (hashType) {
            case NULL -> NULL.INSTANCE;
            case GOSTR341112_256 -> new GOSTR_3411_2012_256();
            case MD5 -> new MD5();
            case SHA1 -> new SHA1();
            case SHA256 -> new SHA256();
            case SHA384 -> new SHA384();
            case SM3 -> new SM3();
        };
    }

    public abstract void update(byte input);

    public abstract void update(ByteBuffer input);

    public abstract void update(byte[] input, int offset, int len);

    public abstract int digest(byte[] output, int offset, int length, boolean reset);

    public abstract void reset();

    public abstract TlsHashType type();

    public void update(byte[] input) {
        update(input, 0, input.length);
    }

    public byte[] digest(boolean reset) {
        var length = type().length();
        var result = new byte[length];
        digest(result, 0, length, reset);
        return result;
    }

    public int digest(byte[] output, int offset, boolean reset) {
        return digest(output, offset, type().length(), reset);
    }

    public int digest(byte[] output, boolean reset) {
        return digest(output, 0, type().length(), reset);
    }

    public byte[] digest(boolean reset, int offset, int length) {
        var result = new byte[length];
        digest(result, offset, length, reset);
        return result;
    }
}
