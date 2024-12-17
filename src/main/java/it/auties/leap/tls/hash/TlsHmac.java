package it.auties.leap.tls.hash;

import java.nio.ByteBuffer;
import java.security.Key;

public final class TlsHmac {
    private final static byte IPAD = (byte) 0x36;
    private final static byte OPAD = (byte) 0x5C;

    public static TlsHmac none() {
        return new TlsHmac(NULLDigest.INSTANCE);
    }

    public static TlsHmac md5() {
        return new TlsHmac(new MD5Digest());
    }

    public static TlsHmac sha1() {
        return new TlsHmac(new SHA1Digest());
    }

    public static TlsHmac sha256() {
        return new TlsHmac(new SHA256Digest());
    }

    public static TlsHmac sha384() {
        return new TlsHmac(new SHA384Digest());
    }

    public static TlsHmac sm3() {
        return new TlsHmac(new SM3Digest());
    }

    public static TlsHmac gostr341112_256() {
        return new TlsHmac(new GOSTR256Digest());
    }

    public static TlsHmac of(TlsHashType hash) {
        return new TlsHmac(hash);
    } 
    
    private final TlsHash hash;
    private byte[] inputPad;
    private byte[] outputBuf;
    private TlsHmac(TlsHashType hash) {
        this.hash = hash.newHash();
    }

    public int minimalPaddingLength() {
        return 1 + ((int) Math.ceil(hash.type().length() / 32f)) * 8;
    }

    public void init(Key javaKey) {
        if(inputPad != null || outputBuf != null) {
            throw new IllegalStateException("Already initialized");
        }

        this.inputPad = new byte[hash.type().blockLength()];
        this.outputBuf = new byte[hash.type().blockLength() + hash.type().length()];

        hash.reset();

        var key = javaKey.getEncoded();
        var keyLength = key.length;
        if (keyLength <= hash.type().blockLength()) {
            System.arraycopy(key, 0, inputPad, 0, keyLength);
        } else {
            hash.update(key, 0, keyLength);
            hash.digest(inputPad, true);
        }

        var start = keyLength <= hash.type().blockLength() ? keyLength : hash.type().length();
        for (int i = start; i < inputPad.length; i++) {
            inputPad[i] = 0;
        }

        System.arraycopy(inputPad, 0, outputBuf, 0, hash.type().blockLength());

        xorPad(inputPad, hash.type().blockLength(), IPAD);
        xorPad(outputBuf, hash.type().blockLength(), OPAD);

        hash.update(inputPad, 0, inputPad.length);
    }

    public void update(byte input) {
        hash.update(input);
    }

    public void update(byte[] input, int offset, int len) {
        hash.update(input, offset, len);
    }

    public void update(byte[] input) {
        hash.update(input);
    }

    public void update(ByteBuffer input) {
        hash.update(input);
    }

    public byte[] doFinal() {
        var length = hash.type().length();
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

        hash.digest(outputBuf, hash.type().blockLength(), true);

        hash.update(outputBuf, 0, outputBuf.length);

        var len = hash.digest(output, offset, true);
        for (var i = hash.type().blockLength(); i < outputBuf.length; i++) {
            outputBuf[i] = 0;
        }

        hash.update(inputPad, 0, inputPad.length);

        return len;
    }

    public void reset() {
        hash.reset();
        hash.update(inputPad, 0, inputPad.length);
    }

    private static void xorPad(byte[] pad, int len, byte n) {
        for (int i = 0; i < len; ++i) {
            pad[i] ^= n;
        }
    }
}
