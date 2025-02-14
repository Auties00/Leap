package it.auties.leap.tls.hash.implementation;

import it.auties.leap.tls.hash.TlsHash;
import it.auties.leap.tls.hash.TlsHashFactory;

import java.nio.ByteBuffer;
import java.util.Arrays;

import static it.auties.leap.tls.util.BufferUtils.*;

public final class SHA384Hash implements TlsHash {
    private static final int BLOCK_LENGTH = 8;
    private static final TlsHashFactory FACTORY = new TlsHashFactory() {
        @Override
        public TlsHash newHash() {
            return new SHA384Hash();
        }

        @Override
        public int length() {
            return 48;
        }
    };

    private long h1;
    private long h2;
    private long h3;
    private long h4;
    private long h5;
    private long h6;
    private long h7;
    private long h8;
    private final long[] w;
    private int wOff;
    private final byte[] xBuf;
    private int xBufOff;
    private long byteCount1;
    private long byteCount2;

    public SHA384Hash() {
        w = new long[80];
        xBuf = new byte[BLOCK_LENGTH];
        reset();
    }

    private SHA384Hash(SHA384Hash other) {
        this.h1 = other.h1;
        this.h2 = other.h2;
        this.h3 = other.h3;
        this.h4 = other.h4;
        this.h5 = other.h5;
        this.h6 = other.h6;
        this.h7 = other.h7;
        this.h8 = other.h8;
        this.w = other.w.clone();
        this.wOff = other.wOff;
        this.xBuf = other.xBuf.clone();
        this.xBufOff = other.xBufOff;
        this.byteCount1 = other.byteCount1;
        this.byteCount2 = other.byteCount2;
    }

    public static TlsHashFactory factory() {
        return FACTORY;
    }

    @Override
    public int digest(byte[] output, int offset, int length, boolean reset) {
        if (reset) {
            adjustByteCounts();

            long lowBitLength = byteCount1 << 3;
            long hiBitLength = byteCount2;

            update((byte) 128);

            while (xBufOff != 0) {
                update((byte) 0);
            }

            processLength(lowBitLength, hiBitLength);

            processBlock();

            writeBigEndianInt64(h1, output, offset);
            writeBigEndianInt64(h2, output, offset + 8);
            writeBigEndianInt64(h3, output, offset + 16);
            writeBigEndianInt64(h4, output, offset + 24);
            writeBigEndianInt64(h5, output, offset + 32);
            writeBigEndianInt64(h6, output, offset + 40);

            reset();

            return length;
        } else {
            var digest = new SHA384Hash(this);
            return digest.digest(output, offset, length, true);
        }
    }

    /**
     * reset the chaining variables
     */
    public void reset() {
        byteCount1 = 0;
        byteCount2 = 0;

        xBufOff = 0;
        Arrays.fill(xBuf, (byte) 0);

        wOff = 0;
        Arrays.fill(w, 0);

        /* SHA-384 initial hash value
         * The first 64 bits of the fractional parts of the square roots
         * of the 9th through 16th prime numbers
         */
        h1 = 0xcbbb9d5dc1059ed8L;
        h2 = 0x629a292a367cd507L;
        h3 = 0x9159015a3070dd17L;
        h4 = 0x152fecd8f70e5939L;
        h5 = 0x67332667ffc00b31L;
        h6 = 0x8eb44a8768581511L;
        h7 = 0xdb0c2e0d64f98fa7L;
        h8 = 0x47b5481dbefa4fa4L;
    }

    @Override
    public void update(byte in) {
        xBuf[xBufOff++] = in;

        if (xBufOff == xBuf.length) {
            processWord(xBuf, 0);
            xBufOff = 0;
        }

        byteCount1++;
    }

    @Override
    public void update(byte[] in, int inOff, int len) {
        //
        // fill the current word
        //
        while ((xBufOff != 0) && (len > 0)) {
            update(in[inOff]);

            inOff++;
            len--;
        }

        //
        // process whole words.
        //
        while (len >= xBuf.length) {
            processWord(in, inOff);

            inOff += xBuf.length;
            len -= xBuf.length;
            byteCount1 += xBuf.length;
        }

        //
        // load in the remainder.
        //
        while (len > 0) {
            update(in[inOff]);

            inOff++;
            len--;
        }
    }

    @Override
    public void update(ByteBuffer input) {
        var inOff = input.position();
        var len = input.remaining();

        //
        // fill the current word
        //
        while ((xBufOff != 0) && (len > 0)) {
            update(input.get(inOff));

            inOff++;
            len--;
        }

        //
        // process whole words.
        //
        while (len >= xBuf.length) {
            processWord(input);

            inOff += xBuf.length;
            len -= xBuf.length;
            byteCount1 += xBuf.length;
        }

        //
        // load in the remainder.
        //
        while (len > 0) {
            update(input.get(inOff));

            inOff++;
            len--;
        }
    }


    private void processWord(byte[] in, int inOff) {
        w[wOff] = readBigEndianInt64(in, inOff);

        if (++wOff == 16) {
            processBlock();
        }
    }

    private void processWord(ByteBuffer in) {
        w[wOff] =  readBigEndianInt64(in);

        if (++wOff == 16) {
            processBlock();
        }
    }


    /**
     * adjust the byte counts so that byteCount2 represents the
     * upper long (less 3 bits) word of the byte count.
     */
    private void adjustByteCounts() {
        if (byteCount1 > 0x1fffffffffffffffL) {
            byteCount2 += (byteCount1 >>> 61);
            byteCount1 &= 0x1fffffffffffffffL;
        }
    }

    private void processLength(long lowW, long hiW) {
        if (wOff > 14) {
            processBlock();
        }

        w[14] = hiW;
        w[15] = lowW;
    }

    private void processBlock() {
        adjustByteCounts();

        //
        // expand 16 word block into 80 word blocks.
        //
        for (int t = 16; t <= 79; t++) {
            w[t] = Sigma1(w[t - 2]) + w[t - 7] + Sigma0(w[t - 15]) + w[t - 16];
        }

        //
        // set up working variables.
        //
        long a = h1;
        long b = h2;
        long c = h3;
        long d = h4;
        long e = h5;
        long f = h6;
        long g = h7;
        long h = h8;

        int t = 0;
        for (int i = 0; i < 10; i++) {
            // t = 8 * i
            h += Sum1(e) + Ch(e, f, g) + K[t] + w[t++];
            d += h;
            h += Sum0(a) + Maj(a, b, c);

            // t = 8 * i + 1
            g += Sum1(d) + Ch(d, e, f) + K[t] + w[t++];
            c += g;
            g += Sum0(h) + Maj(h, a, b);

            // t = 8 * i + 2
            f += Sum1(c) + Ch(c, d, e) + K[t] + w[t++];
            b += f;
            f += Sum0(g) + Maj(g, h, a);

            // t = 8 * i + 3
            e += Sum1(b) + Ch(b, c, d) + K[t] + w[t++];
            a += e;
            e += Sum0(f) + Maj(f, g, h);

            // t = 8 * i + 4
            d += Sum1(a) + Ch(a, b, c) + K[t] + w[t++];
            h += d;
            d += Sum0(e) + Maj(e, f, g);

            // t = 8 * i + 5
            c += Sum1(h) + Ch(h, a, b) + K[t] + w[t++];
            g += c;
            c += Sum0(d) + Maj(d, e, f);

            // t = 8 * i + 6
            b += Sum1(g) + Ch(g, h, a) + K[t] + w[t++];
            f += b;
            b += Sum0(c) + Maj(c, d, e);

            // t = 8 * i + 7
            a += Sum1(f) + Ch(f, g, h) + K[t] + w[t++];
            e += a;
            a += Sum0(b) + Maj(b, c, d);
        }

        h1 += a;
        h2 += b;
        h3 += c;
        h4 += d;
        h5 += e;
        h6 += f;
        h7 += g;
        h8 += h;

        //
        // reset the offset and clean out the word buffer.
        //
        wOff = 0;
        for (int i = 0; i < 16; i++) {
            w[i] = 0;
        }
    }

    /* SHA-384 and SHA-512 functions (as for SHA-256 but for longs) */
    private long Ch(long x, long y, long z) {
        return ((x & y) ^ ((~x) & z));
    }

    private long Maj(long x, long y, long z) {
        return ((x & y) ^ (x & z) ^ (y & z));
    }

    private long Sum0(long x) {
        return ((x << 36) | (x >>> 28)) ^ ((x << 30) | (x >>> 34)) ^ ((x << 25) | (x >>> 39));
    }

    private long Sum1(long x) {
        return ((x << 50) | (x >>> 14)) ^ ((x << 46) | (x >>> 18)) ^ ((x << 23) | (x >>> 41));
    }

    private long Sigma0(long x) {
        return ((x << 63) | (x >>> 1)) ^ ((x << 56) | (x >>> 8)) ^ (x >>> 7);
    }

    private long Sigma1(long x) {
        return ((x << 45) | (x >>> 19)) ^ ((x << 3) | (x >>> 61)) ^ (x >>> 6);
    }

    /* SHA-384 and SHA-512 Constants
     * (represent the first 64 bits of the fractional parts of the
     * cube roots of the first sixty-four prime numbers)
     */
    static final long[] K = {0x428a2f98d728ae22L, 0x7137449123ef65cdL, 0xb5c0fbcfec4d3b2fL, 0xe9b5dba58189dbbcL, 0x3956c25bf348b538L, 0x59f111f1b605d019L, 0x923f82a4af194f9bL, 0xab1c5ed5da6d8118L, 0xd807aa98a3030242L, 0x12835b0145706fbeL, 0x243185be4ee4b28cL, 0x550c7dc3d5ffb4e2L, 0x72be5d74f27b896fL, 0x80deb1fe3b1696b1L, 0x9bdc06a725c71235L, 0xc19bf174cf692694L, 0xe49b69c19ef14ad2L, 0xefbe4786384f25e3L, 0x0fc19dc68b8cd5b5L, 0x240ca1cc77ac9c65L, 0x2de92c6f592b0275L, 0x4a7484aa6ea6e483L, 0x5cb0a9dcbd41fbd4L, 0x76f988da831153b5L, 0x983e5152ee66dfabL, 0xa831c66d2db43210L, 0xb00327c898fb213fL, 0xbf597fc7beef0ee4L, 0xc6e00bf33da88fc2L, 0xd5a79147930aa725L, 0x06ca6351e003826fL, 0x142929670a0e6e70L, 0x27b70a8546d22ffcL, 0x2e1b21385c26c926L, 0x4d2c6dfc5ac42aedL, 0x53380d139d95b3dfL, 0x650a73548baf63deL, 0x766a0abb3c77b2a8L, 0x81c2c92e47edaee6L, 0x92722c851482353bL, 0xa2bfe8a14cf10364L, 0xa81a664bbc423001L, 0xc24b8b70d0f89791L, 0xc76c51a30654be30L, 0xd192e819d6ef5218L, 0xd69906245565a910L, 0xf40e35855771202aL, 0x106aa07032bbd1b8L, 0x19a4c116b8d2d0c8L, 0x1e376c085141ab53L, 0x2748774cdf8eeb99L, 0x34b0bcb5e19b48a8L, 0x391c0cb3c5c95a63L, 0x4ed8aa4ae3418acbL, 0x5b9cca4f7763e373L, 0x682e6ff3d6b2b8a3L, 0x748f82ee5defb2fcL, 0x78a5636f43172f60L, 0x84c87814a1f0ab72L, 0x8cc702081a6439ecL, 0x90befffa23631e28L, 0xa4506cebde82bde9L, 0xbef9a3f7b2c67915L, 0xc67178f2e372532bL, 0xca273eceea26619cL, 0xd186b8c721c0c207L, 0xeada7dd6cde0eb1eL, 0xf57d4f7fee6ed178L, 0x06f067aa72176fbaL, 0x0a637dc5a2c898a6L, 0x113f9804bef90daeL, 0x1b710b35131c471bL, 0x28db77f523047d84L, 0x32caab7b40c72493L, 0x3c9ebe0a15c9bebcL, 0x431d67c49c100d4cL, 0x4cc5d4becb3e42b6L, 0x597f299cfc657e2aL, 0x5fcb6fab3ad6faecL, 0x6c44198c4a475817L};


    @Override
    public int length() {
        return 48;
    }

    @Override
    public int blockLength() {
        return 128;
    }

    @Override
    public TlsHash duplicate() {
        return new SHA384Hash();
    }
}
