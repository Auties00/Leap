package it.auties.leap.tls.hash.implementation;

import it.auties.leap.tls.hash.TlsHash;
import it.auties.leap.tls.hash.TlsHashFactory;

import java.nio.ByteBuffer;
import java.util.Arrays;

import static it.auties.leap.tls.util.BufferUtils.readBigEndianInt32;
import static it.auties.leap.tls.util.BufferUtils.writeBigEndianInt32;

public final class SHA224Hash implements TlsHash {
    private static final int BLOCK_LENGTH = 4;
    private static final TlsHashFactory FACTORY = new TlsHashFactory() {
        @Override
        public TlsHash newHash() {
            return new SHA224Hash();
        }

        @Override
        public int length() {
            return 28;
        }
    };

    private int h1;
    private int h2;
    private int h3;
    private int h4;
    private int h5;
    private int h6;
    private int h7;
    private int h8;
    private final int[] x;
    private int xOff;
    private final byte[] xBuf;
    private int xBufOff;
    private long byteCount;

    public SHA224Hash() {
        x = new int[64];
        xBuf = new byte[BLOCK_LENGTH];
        reset();
    }

    private SHA224Hash(SHA224Hash other) {
        this.h1 = other.h1;
        this.h2 = other.h2;
        this.h3 = other.h3;
        this.h4 = other.h4;
        this.h5 = other.h5;
        this.h6 = other.h6;
        this.h7 = other.h7;
        this.h8 = other.h8;
        this.x = other.x.clone();
        this.xOff = other.xOff;
        this.xBuf = other.xBuf.clone();
        this.xBufOff = other.xBufOff;
        this.byteCount = other.byteCount;
    }

    public static TlsHashFactory factory() {
        return FACTORY;
    }

    @Override
    public void update(byte in) {
        xBuf[xBufOff++] = in;

        if (xBufOff == xBuf.length) {
            processWord(xBuf, 0);
            xBufOff = 0;
        }

        byteCount++;
    }

    @Override
    public void update(byte[] in, int inOff, int len) {
        len = Math.max(0, len);

        int i = 0;
        if (xBufOff != 0) {
            while (i < len) {
                xBuf[xBufOff++] = in[inOff + i++];
                if (xBufOff == 4) {
                    processWord(xBuf, 0);
                    xBufOff = 0;
                    break;
                }
            }
        }

        int limit = len - 3;
        for (; i < limit; i += 4) {
            processWord(in, inOff + i);
        }

        while (i < len) {
            xBuf[xBufOff++] = in[inOff + i++];
        }

        byteCount += len;
    }

    @Override
    public void update(ByteBuffer input) {
        var len = input.remaining();

        if (xBufOff != 0) {
            while (input.hasRemaining()) {
                xBuf[xBufOff++] = input.get();
                if (xBufOff == 4) {
                    processWord(xBuf, 0);
                    xBufOff = 0;
                    break;
                }
            }
        }

        while (input.remaining() >= BLOCK_LENGTH) {
            processWord(input);
        }

        while (input.hasRemaining()) {
            xBuf[xBufOff++] = input.get();
        }

        byteCount += len;
    }

    private void processWord(byte[] in, int inOff) {
        x[xOff] = readBigEndianInt32(in, inOff);

        if (++xOff == 16) {
            processBlock();
        }
    }

    private void processWord(ByteBuffer in) {
        x[xOff] = readBigEndianInt32(in);

        if (++xOff == 16) {
            processBlock();
        }
    }


    private void processLength(long bitLength) {
        if (xOff > 14) {
            processBlock();
        }

        x[14] = (int) (bitLength >>> 32);
        x[15] = (int) (bitLength);
    }

    @Override
    public int digest(byte[] output, int offset, int length, boolean reset) {
        if (reset) {
            long bitLength = (byteCount << 3);

            update((byte) 128);

            while (xBufOff != 0) {
                update((byte) 0);
            }

            processLength(bitLength);

            processBlock();

            writeBigEndianInt32(h1, output, offset);
            writeBigEndianInt32(h2, output, offset + 4);
            writeBigEndianInt32(h3, output, offset + 8);
            writeBigEndianInt32(h4, output, offset + 12);
            writeBigEndianInt32(h5, output, offset + 16);
            writeBigEndianInt32(h6, output, offset + 20);
            writeBigEndianInt32(h7, output, offset + 24);

            reset();

            return length;
        } else {
            var digest = new SHA224Hash(this);
            return digest.digest(output, offset, length, true);
        }
    }

    /**
     * reset the chaining variables
     */
    public void reset() {
        byteCount = 0;

        xBufOff = 0;
        Arrays.fill(xBuf, (byte) 0);

        /* SHA-256 initial hash value
         * The first 32 bits of the fractional parts of the square roots
         * of the first eight prime numbers
         */

        h1 = 0xc1059ed8;
        h2 = 0x367cd507;
        h3 = 0x3070dd17;
        h4 = 0xf70e5939;
        h5 = 0xffc00b31;
        h6 = 0x68581511;
        h7 = 0x64f98fa7;
        h8 = 0xbefa4fa4;

        xOff = 0;
        Arrays.fill(x, 0);
    }

    private void processBlock() {
        //
        // expand 16 word block into 64 word blocks.
        //
        for (int t = 16; t <= 63; t++) {
            x[t] = Theta1(x[t - 2]) + x[t - 7] + Theta0(x[t - 15]) + x[t - 16];
        }

        //
        // set up working variables.
        //
        int a = h1;
        int b = h2;
        int c = h3;
        int d = h4;
        int e = h5;
        int f = h6;
        int g = h7;
        int h = h8;

        int t = 0;
        for (int i = 0; i < 8; i++) {
            // t = 8 * i
            h += Sum1(e) + Ch(e, f, g) + K[t] + x[t];
            d += h;
            h += Sum0(a) + Maj(a, b, c);
            ++t;

            // t = 8 * i + 1
            g += Sum1(d) + Ch(d, e, f) + K[t] + x[t];
            c += g;
            g += Sum0(h) + Maj(h, a, b);
            ++t;

            // t = 8 * i + 2
            f += Sum1(c) + Ch(c, d, e) + K[t] + x[t];
            b += f;
            f += Sum0(g) + Maj(g, h, a);
            ++t;

            // t = 8 * i + 3
            e += Sum1(b) + Ch(b, c, d) + K[t] + x[t];
            a += e;
            e += Sum0(f) + Maj(f, g, h);
            ++t;

            // t = 8 * i + 4
            d += Sum1(a) + Ch(a, b, c) + K[t] + x[t];
            h += d;
            d += Sum0(e) + Maj(e, f, g);
            ++t;

            // t = 8 * i + 5
            c += Sum1(h) + Ch(h, a, b) + K[t] + x[t];
            g += c;
            c += Sum0(d) + Maj(d, e, f);
            ++t;

            // t = 8 * i + 6
            b += Sum1(g) + Ch(g, h, a) + K[t] + x[t];
            f += b;
            b += Sum0(c) + Maj(c, d, e);
            ++t;

            // t = 8 * i + 7
            a += Sum1(f) + Ch(f, g, h) + K[t] + x[t];
            e += a;
            a += Sum0(b) + Maj(b, c, d);
            ++t;
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
        xOff = 0;
        for (int i = 0; i < 16; i++) {
            x[i] = 0;
        }
    }

    /* SHA-256 functions */
    private static int Ch(int x, int y, int z) {
        return (x & y) ^ ((~x) & z);
//        return z ^ (x & (y ^ z));
    }

    private static int Maj(int x, int y, int z) {
//        return (x & y) ^ (x & z) ^ (y & z);
        return (x & y) | (z & (x ^ y));
    }

    private static int Sum0(int x) {
        return ((x >>> 2) | (x << 30)) ^ ((x >>> 13) | (x << 19)) ^ ((x >>> 22) | (x << 10));
    }

    private static int Sum1(int x) {
        return ((x >>> 6) | (x << 26)) ^ ((x >>> 11) | (x << 21)) ^ ((x >>> 25) | (x << 7));
    }

    private static int Theta0(int x) {
        return ((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3);
    }

    private static int Theta1(int x) {
        return ((x >>> 17) | (x << 15)) ^ ((x >>> 19) | (x << 13)) ^ (x >>> 10);
    }

    /* SHA-256 Constants
     * (represent the first 32 bits of the fractional parts of the
     * cube roots of the first sixty-four prime numbers)
     */
    static final int[] K = {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

    @Override
    public int length() {
        return 28;
    }

    @Override
    public int blockLength() {
        return 64;
    }

    @Override
    public TlsHash duplicate() {
        return new SHA224Hash();
    }
}
