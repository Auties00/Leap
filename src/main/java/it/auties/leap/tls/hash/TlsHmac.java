package it.auties.leap.tls.hash;

import it.auties.leap.tls.TlsHmacType;

import java.nio.ByteBuffer;
import java.security.Key;

public final class TlsHmac {
    private final static byte IPAD = (byte) 0x36;
    private final static byte OPAD = (byte) 0x5C;

    private final TlsHmacType type;
    private final TlsHash digest;
    private byte[] inputPad;
    private byte[] outputBuf;
    private TlsHmac(TlsHmacType type, TlsHash digest) {
        this.type = type;
        this.digest = digest;
    }

    public static TlsHmac of(TlsHmacType tlsHmacType) {
        var digest = TlsHash.of(tlsHmacType.toHash());
        return new TlsHmac(tlsHmacType, digest);
    }

    public TlsHmacType type() {
        return type;
    }

    public void init(Key javaKey) {
        if(inputPad != null || outputBuf != null) {
            throw new IllegalStateException("Already initialized");
        }

        this.inputPad = new byte[type.toHash().blockLength()];
        this.outputBuf = new byte[type.toHash().blockLength() + type.toHash().length()];

        digest.reset();

        var key = javaKey.getEncoded();
        var keyLength = key.length;
        if (keyLength <= type.toHash().blockLength()) {
            System.arraycopy(key, 0, inputPad, 0, keyLength);
        } else {
            digest.update(key, 0, keyLength);
            digest.digest(inputPad, true);
        }

        var start = keyLength <= type.toHash().blockLength() ? keyLength : type.toHash().length();
        for (int i = start; i < inputPad.length; i++) {
            inputPad[i] = 0;
        }

        System.arraycopy(inputPad, 0, outputBuf, 0, type.toHash().blockLength());

        xorPad(inputPad, type.toHash().blockLength(), IPAD);
        xorPad(outputBuf, type.toHash().blockLength(), OPAD);

        digest.update(inputPad, 0, inputPad.length);
    }

    public void update(byte input) {
        digest.update(input);
    }

    public void update(byte[] input, int offset, int len) {
        digest.update(input, offset, len);
    }

    public void update(byte[] input) {
        digest.update(input);
    }

    public void update(ByteBuffer input) {
        digest.update(input);
    }

    public byte[] doFinal() {
        var length = type().length();
        var result = new byte[length];
        if(length != doFinal(result, 0)) {
            throw new RuntimeException("Length mismatch");
        }

        return result;
    }

    public int doFinal(byte[] output, int offset) {
        if(inputPad == null || outputBuf == null) {
            throw new IllegalStateException("Not initialized");
        }

        digest.digest(outputBuf, type.toHash().blockLength(), true);

        digest.update(outputBuf, 0, outputBuf.length);

        var len = digest.digest(output, offset, true);
        for (var i = type.toHash().blockLength(); i < outputBuf.length; i++) {
            outputBuf[i] = 0;
        }

        digest.update(inputPad, 0, inputPad.length);

        return len;
    }

    public void reset() {
        digest.reset();
        digest.update(inputPad, 0, inputPad.length);
    }

    private static void xorPad(byte[] pad, int len, byte n) {
        for (int i = 0; i < len; ++i) {
            pad[i] ^= n;
        }
    }
}
