package it.auties.leap.tls.hash;

import it.auties.leap.tls.BufferHelper;

import java.nio.ByteBuffer;
import java.util.Arrays;

import static it.auties.leap.tls.BufferHelper.readLittleEndianInt32;

final class MD5Hash implements TlsHash {
    private static final int BLOCK_LENGTH = 4;

    private int h1;
    private int h2;
    private int h3;
    private int h4;
    private final int[] x;
    private int xOff;
    private final byte[] xBuf;
    private int xBufOff;
    private long byteCount;

    MD5Hash() {
        x = new int[16];
        xBuf = new byte[BLOCK_LENGTH];
        reset();
    }

    private MD5Hash(MD5Hash other) {
        this.h1 = other.h1;
        this.h2 = other.h2;
        this.h3 = other.h3;
        this.h4 = other.h4;
        this.x = other.x.clone();
        this.xOff = other.xOff;
        this.xBuf = other.xBuf.clone();
        this.xBufOff = other.xBufOff;
        this.byteCount = other.byteCount;
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
    public void update(ByteBuffer input) {
        var inOff = input.position();
        var len = input.remaining();

        //
        // fill the current word
        //
        int i = 0;
        if (xBufOff != 0) {
            while (i < len) {
                xBuf[xBufOff++] = input.get(inOff + i++);
                if (xBufOff == 4) {
                    processWord(xBuf, 0);
                    xBufOff = 0;
                    break;
                }
            }
        }

        //
        // process whole words.
        //
        int limit = len - 3;
        for (; i < limit; i += 4) {
            processWord(input);
        }

        //
        // load in the remainder.
        //
        while (i < len) {
            xBuf[xBufOff++] = input.get(inOff + i++);
        }

        byteCount += len;
    }

    @Override
    public void update(byte[] in, int inOff, int len) {
        len = Math.max(0, len);

        //
        // fill the current word
        //
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

        //
        // process whole words.
        //
        int limit = len - 3;
        for (; i < limit; i += 4) {
            processWord(in, inOff + i);
        }

        //
        // load in the remainder.
        //
        while (i < len) {
            xBuf[xBufOff++] = in[inOff + i++];
        }

        byteCount += len;
    }

    private void processWord(byte[] in, int inOff) {
        x[xOff++] = readLittleEndianInt32(in, inOff);

        if (xOff == 16) {
            processBlock();
        }
    }

    private void processWord(ByteBuffer in) {
        x[xOff++] = readLittleEndianInt32(in);

        if (xOff == 16) {
            processBlock();
        }
    }

    private void processLength(long bitLength) {
        if (xOff > 14) {
            processBlock();
        }

        x[14] = (int) (bitLength);
        x[15] = (int) (bitLength >>> 32);
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

            BufferHelper.writeLittleEndianInt32(h1, output, offset);
            BufferHelper.writeLittleEndianInt32(h2, output, offset + 4);
            BufferHelper.writeLittleEndianInt32(h3, output, offset + 8);
            BufferHelper.writeLittleEndianInt32(h4, output, offset + 12);

            reset();

            return length;
        } else {
            var digest = new MD5Hash(this);
            return digest.digest(output, offset, length, true);
        }
    }

    /**
     * reset the chaining variables to the IV values.
     */
    @Override
    public void reset() {
        byteCount = 0;

        xBufOff = 0;
        Arrays.fill(xBuf, (byte) 0);

        h1 = 0x67452301;
        h2 = 0xefcdab89;
        h3 = 0x98badcfe;
        h4 = 0x10325476;

        xOff = 0;

        Arrays.fill(x, 0);
    }

    //
    // round 1 left rotates
    //
    private static final int S11 = 7;
    private static final int S12 = 12;
    private static final int S13 = 17;
    private static final int S14 = 22;

    //
    // round 2 left rotates
    //
    private static final int S21 = 5;
    private static final int S22 = 9;
    private static final int S23 = 14;
    private static final int S24 = 20;

    //
    // round 3 left rotates
    //
    private static final int S31 = 4;
    private static final int S32 = 11;
    private static final int S33 = 16;
    private static final int S34 = 23;

    //
    // round 4 left rotates
    //
    private static final int S41 = 6;
    private static final int S42 = 10;
    private static final int S43 = 15;
    private static final int S44 = 21;

    /*
     * rotate int x left n bits.
     */
    private int rotateLeft(int x, int n) {
        return (x << n) | (x >>> (32 - n));
    }

    /*
     * F, G, H and I are the basic MD5 functions.
     */
    private int F(int u, int v, int w) {
        return (u & v) | (~u & w);
    }

    private int G(int u, int v, int w) {
        return (u & w) | (v & ~w);
    }

    private int H(int u, int v, int w) {
        return u ^ v ^ w;
    }

    private int K(int u, int v, int w) {
        return v ^ (u | ~w);
    }

    private void processBlock() {
        int a = h1;
        int b = h2;
        int c = h3;
        int d = h4;

        //
        // Round 1 - F cycle, 16 times.
        //
        a = rotateLeft(a + F(b, c, d) + x[0] + 0xd76aa478, S11) + b;
        d = rotateLeft(d + F(a, b, c) + x[1] + 0xe8c7b756, S12) + a;
        c = rotateLeft(c + F(d, a, b) + x[2] + 0x242070db, S13) + d;
        b = rotateLeft(b + F(c, d, a) + x[3] + 0xc1bdceee, S14) + c;
        a = rotateLeft(a + F(b, c, d) + x[4] + 0xf57c0faf, S11) + b;
        d = rotateLeft(d + F(a, b, c) + x[5] + 0x4787c62a, S12) + a;
        c = rotateLeft(c + F(d, a, b) + x[6] + 0xa8304613, S13) + d;
        b = rotateLeft(b + F(c, d, a) + x[7] + 0xfd469501, S14) + c;
        a = rotateLeft(a + F(b, c, d) + x[8] + 0x698098d8, S11) + b;
        d = rotateLeft(d + F(a, b, c) + x[9] + 0x8b44f7af, S12) + a;
        c = rotateLeft(c + F(d, a, b) + x[10] + 0xffff5bb1, S13) + d;
        b = rotateLeft(b + F(c, d, a) + x[11] + 0x895cd7be, S14) + c;
        a = rotateLeft(a + F(b, c, d) + x[12] + 0x6b901122, S11) + b;
        d = rotateLeft(d + F(a, b, c) + x[13] + 0xfd987193, S12) + a;
        c = rotateLeft(c + F(d, a, b) + x[14] + 0xa679438e, S13) + d;
        b = rotateLeft(b + F(c, d, a) + x[15] + 0x49b40821, S14) + c;

        //
        // Round 2 - G cycle, 16 times.
        //
        a = rotateLeft(a + G(b, c, d) + x[1] + 0xf61e2562, S21) + b;
        d = rotateLeft(d + G(a, b, c) + x[6] + 0xc040b340, S22) + a;
        c = rotateLeft(c + G(d, a, b) + x[11] + 0x265e5a51, S23) + d;
        b = rotateLeft(b + G(c, d, a) + x[0] + 0xe9b6c7aa, S24) + c;
        a = rotateLeft(a + G(b, c, d) + x[5] + 0xd62f105d, S21) + b;
        d = rotateLeft(d + G(a, b, c) + x[10] + 0x02441453, S22) + a;
        c = rotateLeft(c + G(d, a, b) + x[15] + 0xd8a1e681, S23) + d;
        b = rotateLeft(b + G(c, d, a) + x[4] + 0xe7d3fbc8, S24) + c;
        a = rotateLeft(a + G(b, c, d) + x[9] + 0x21e1cde6, S21) + b;
        d = rotateLeft(d + G(a, b, c) + x[14] + 0xc33707d6, S22) + a;
        c = rotateLeft(c + G(d, a, b) + x[3] + 0xf4d50d87, S23) + d;
        b = rotateLeft(b + G(c, d, a) + x[8] + 0x455a14ed, S24) + c;
        a = rotateLeft(a + G(b, c, d) + x[13] + 0xa9e3e905, S21) + b;
        d = rotateLeft(d + G(a, b, c) + x[2] + 0xfcefa3f8, S22) + a;
        c = rotateLeft(c + G(d, a, b) + x[7] + 0x676f02d9, S23) + d;
        b = rotateLeft(b + G(c, d, a) + x[12] + 0x8d2a4c8a, S24) + c;

        //
        // Round 3 - H cycle, 16 times.
        //
        a = rotateLeft(a + H(b, c, d) + x[5] + 0xfffa3942, S31) + b;
        d = rotateLeft(d + H(a, b, c) + x[8] + 0x8771f681, S32) + a;
        c = rotateLeft(c + H(d, a, b) + x[11] + 0x6d9d6122, S33) + d;
        b = rotateLeft(b + H(c, d, a) + x[14] + 0xfde5380c, S34) + c;
        a = rotateLeft(a + H(b, c, d) + x[1] + 0xa4beea44, S31) + b;
        d = rotateLeft(d + H(a, b, c) + x[4] + 0x4bdecfa9, S32) + a;
        c = rotateLeft(c + H(d, a, b) + x[7] + 0xf6bb4b60, S33) + d;
        b = rotateLeft(b + H(c, d, a) + x[10] + 0xbebfbc70, S34) + c;
        a = rotateLeft(a + H(b, c, d) + x[13] + 0x289b7ec6, S31) + b;
        d = rotateLeft(d + H(a, b, c) + x[0] + 0xeaa127fa, S32) + a;
        c = rotateLeft(c + H(d, a, b) + x[3] + 0xd4ef3085, S33) + d;
        b = rotateLeft(b + H(c, d, a) + x[6] + 0x04881d05, S34) + c;
        a = rotateLeft(a + H(b, c, d) + x[9] + 0xd9d4d039, S31) + b;
        d = rotateLeft(d + H(a, b, c) + x[12] + 0xe6db99e5, S32) + a;
        c = rotateLeft(c + H(d, a, b) + x[15] + 0x1fa27cf8, S33) + d;
        b = rotateLeft(b + H(c, d, a) + x[2] + 0xc4ac5665, S34) + c;

        //
        // Round 4 - K cycle, 16 times.
        //
        a = rotateLeft(a + K(b, c, d) + x[0] + 0xf4292244, S41) + b;
        d = rotateLeft(d + K(a, b, c) + x[7] + 0x432aff97, S42) + a;
        c = rotateLeft(c + K(d, a, b) + x[14] + 0xab9423a7, S43) + d;
        b = rotateLeft(b + K(c, d, a) + x[5] + 0xfc93a039, S44) + c;
        a = rotateLeft(a + K(b, c, d) + x[12] + 0x655b59c3, S41) + b;
        d = rotateLeft(d + K(a, b, c) + x[3] + 0x8f0ccc92, S42) + a;
        c = rotateLeft(c + K(d, a, b) + x[10] + 0xffeff47d, S43) + d;
        b = rotateLeft(b + K(c, d, a) + x[1] + 0x85845dd1, S44) + c;
        a = rotateLeft(a + K(b, c, d) + x[8] + 0x6fa87e4f, S41) + b;
        d = rotateLeft(d + K(a, b, c) + x[15] + 0xfe2ce6e0, S42) + a;
        c = rotateLeft(c + K(d, a, b) + x[6] + 0xa3014314, S43) + d;
        b = rotateLeft(b + K(c, d, a) + x[13] + 0x4e0811a1, S44) + c;
        a = rotateLeft(a + K(b, c, d) + x[4] + 0xf7537e82, S41) + b;
        d = rotateLeft(d + K(a, b, c) + x[11] + 0xbd3af235, S42) + a;
        c = rotateLeft(c + K(d, a, b) + x[2] + 0x2ad7d2bb, S43) + d;
        b = rotateLeft(b + K(c, d, a) + x[9] + 0xeb86d391, S44) + c;

        h1 += a;
        h2 += b;
        h3 += c;
        h4 += d;

        //
        // reset the offset and clean out the word buffer.
        //
        xOff = 0;
        Arrays.fill(x, 0);
    }

    @Override
    public int length() {
        return 16;
    }

    @Override
    public int blockLength() {
        return 64;
    }
}
