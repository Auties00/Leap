package it.auties.leap.tls.hash;

import java.nio.ByteBuffer;

public final class TlsHmac {
    private final static byte IPAD = (byte) 0x36;
    private final static byte OPAD = (byte) 0x5C;

    public static TlsHmac none() {
        return new TlsHmac(TlsHash.none());
    }

    public static TlsHmac md5() {
        return new TlsHmac(TlsHash.md5());
    }

    public static TlsHmac sha1() {
        return new TlsHmac(TlsHash.sha1());
    }

    public static TlsHmac sha256() {
        return new TlsHmac(TlsHash.sha256());
    }

    public static TlsHmac sha384() {
        return new TlsHmac(TlsHash.sha384());
    }

    public static TlsHmac sm3() {
        return new TlsHmac(TlsHash.sm3());
    }

    public static TlsHmac gostr256() {
        return new TlsHmac(TlsHash.gostr341112_256());
    }

    public static TlsHmac of(TlsHash hash) {
        return new TlsHmac(hash);
    } 
    
    private final TlsHash hash;
    private byte[] inputPad;
    private byte[] outputBuf;
    private TlsHmac(TlsHash hash) {
        this.hash = hash;
    }

    public int minimalPaddingLength() {
        return 1 + ((int) Math.ceil(hash.length() / 32f)) * 8;
    }

    public int length() {
        return hash.length();
    }

    public int blockLength() {
        return hash.blockLength();
    }

    public void init(byte[] key) {
        if(inputPad != null || outputBuf != null) {
            throw new IllegalStateException("Already initialized");
        }

        this.inputPad = new byte[hash.blockLength()];
        this.outputBuf = new byte[hash.blockLength() + hash.length()];

        hash.reset();

        var keyLength = key.length;
        if (keyLength <= hash.blockLength()) {
            System.arraycopy(key, 0, inputPad, 0, keyLength);
        } else {
            hash.update(key, 0, keyLength);
            hash.digest(inputPad, true);
        }

        var start = keyLength <= hash.blockLength() ? keyLength : hash.length();
        for (int i = start; i < inputPad.length; i++) {
            inputPad[i] = 0;
        }

        System.arraycopy(inputPad, 0, outputBuf, 0, hash.blockLength());

        xorPad(inputPad, hash.blockLength(), IPAD);
        xorPad(outputBuf, hash.blockLength(), OPAD);

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
        var length = hash.length();
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

        hash.digest(outputBuf, hash.blockLength(), true);

        hash.update(outputBuf, 0, outputBuf.length);

        var len = hash.digest(output, offset, true);
        for (var i = hash.blockLength(); i < outputBuf.length; i++) {
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
