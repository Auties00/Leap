package it.auties.leap.tls.hash.implementation;

import it.auties.leap.tls.hash.TlsHash;
import it.auties.leap.tls.hash.TlsHashFactory;

import java.nio.ByteBuffer;
import java.util.Arrays;

import static it.auties.leap.tls.util.BufferUtils.*;

public final class SHA1Hash implements TlsHash {
    private static final int BLOCK_LENGTH = 4;
    private static final TlsHashFactory FACTORY = new TlsHashFactory() {
        @Override
        public TlsHash newHash() {
            return new SHA1Hash();
        }

        @Override
        public int length() {
            return 20;
        }
    };

    private int h1;
    private int h2;
    private int h3;
    private int h4;
    private int h5;
    private final int[] x;
    private int xOff;
    private final byte[] xBuf;
    private int xBufOff;
    private long byteCount;

    public SHA1Hash() {
        x = new int[80];
        xBuf = new byte[BLOCK_LENGTH];
        reset();
    }

    private SHA1Hash(SHA1Hash other) {
        this.h1 = other.h1;
        this.h2 = other.h2;
        this.h3 = other.h3;
        this.h4 = other.h4;
        this.h5 = other.h5;
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
        var inOff = input.position();
        var len = input.remaining();

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

        int limit = len - 3;
        for (; i < limit; i += 4) {
            processWord(input);
        }

        while (i < len) {
            xBuf[xBufOff++] = input.get(inOff + i++);
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
        x[15] = (int) bitLength;
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

            reset();

            return length;
        } else {
            var digest = new SHA1Hash(this);
            return digest.digest(output, offset, length, true);
        }
    }

    /**
     * reset the chaining variables
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
        h5 = 0xc3d2e1f0;

        xOff = 0;
        Arrays.fill(x, 0);
    }

    //
    // Additive constants
    //
    private static final int Y1 = 0x5a827999;
    private static final int Y2 = 0x6ed9eba1;
    private static final int Y3 = 0x8f1bbcdc;
    private static final int Y4 = 0xca62c1d6;

    private int f(int u, int v, int w) {
        return ((u & v) | ((~u) & w));
    }

    private int h(int u, int v, int w) {
        return (u ^ v ^ w);
    }

    private int g(int u, int v, int w) {
        return ((u & v) | (u & w) | (v & w));
    }

    private void processBlock() {
        //
        // expand 16 word block into 80 word block.
        //
        for (int i = 16; i < 80; i++) {
            int t = x[i - 3] ^ x[i - 8] ^ x[i - 14] ^ x[i - 16];
            x[i] = t << 1 | t >>> 31;
        }

        //
        // set up working variables.
        //
        int A = h1;
        int B = h2;
        int C = h3;
        int D = h4;
        int E = h5;

        //
        // round 1
        //
        int idx = 0;

        for (int j = 0; j < 4; j++) {
            // E = rotateLeft(A, 5) + f(B, C, D) + E + X[idx++] + Y1
            // B = rotateLeft(B, 30)
            E += (A << 5 | A >>> 27) + f(B, C, D) + x[idx++] + Y1;
            B = B << 30 | B >>> 2;

            D += (E << 5 | E >>> 27) + f(A, B, C) + x[idx++] + Y1;
            A = A << 30 | A >>> 2;

            C += (D << 5 | D >>> 27) + f(E, A, B) + x[idx++] + Y1;
            E = E << 30 | E >>> 2;

            B += (C << 5 | C >>> 27) + f(D, E, A) + x[idx++] + Y1;
            D = D << 30 | D >>> 2;

            A += (B << 5 | B >>> 27) + f(C, D, E) + x[idx++] + Y1;
            C = C << 30 | C >>> 2;
        }

        //
        // round 2
        //
        for (int j = 0; j < 4; j++) {
            // E = rotateLeft(A, 5) + h(B, C, D) + E + X[idx++] + Y2
            // B = rotateLeft(B, 30)
            E += (A << 5 | A >>> 27) + h(B, C, D) + x[idx++] + Y2;
            B = B << 30 | B >>> 2;

            D += (E << 5 | E >>> 27) + h(A, B, C) + x[idx++] + Y2;
            A = A << 30 | A >>> 2;

            C += (D << 5 | D >>> 27) + h(E, A, B) + x[idx++] + Y2;
            E = E << 30 | E >>> 2;

            B += (C << 5 | C >>> 27) + h(D, E, A) + x[idx++] + Y2;
            D = D << 30 | D >>> 2;

            A += (B << 5 | B >>> 27) + h(C, D, E) + x[idx++] + Y2;
            C = C << 30 | C >>> 2;
        }

        //
        // round 3
        //
        for (int j = 0; j < 4; j++) {
            // E = rotateLeft(A, 5) + g(B, C, D) + E + X[idx++] + Y3
            // B = rotateLeft(B, 30)
            E += (A << 5 | A >>> 27) + g(B, C, D) + x[idx++] + Y3;
            B = B << 30 | B >>> 2;

            D += (E << 5 | E >>> 27) + g(A, B, C) + x[idx++] + Y3;
            A = A << 30 | A >>> 2;

            C += (D << 5 | D >>> 27) + g(E, A, B) + x[idx++] + Y3;
            E = E << 30 | E >>> 2;

            B += (C << 5 | C >>> 27) + g(D, E, A) + x[idx++] + Y3;
            D = D << 30 | D >>> 2;

            A += (B << 5 | B >>> 27) + g(C, D, E) + x[idx++] + Y3;
            C = C << 30 | C >>> 2;
        }

        //
        // round 4
        //
        for (int j = 0; j <= 3; j++) {
            // E = rotateLeft(A, 5) + h(B, C, D) + E + X[idx++] + Y4
            // B = rotateLeft(B, 30)
            E += (A << 5 | A >>> 27) + h(B, C, D) + x[idx++] + Y4;
            B = B << 30 | B >>> 2;

            D += (E << 5 | E >>> 27) + h(A, B, C) + x[idx++] + Y4;
            A = A << 30 | A >>> 2;

            C += (D << 5 | D >>> 27) + h(E, A, B) + x[idx++] + Y4;
            E = E << 30 | E >>> 2;

            B += (C << 5 | C >>> 27) + h(D, E, A) + x[idx++] + Y4;
            D = D << 30 | D >>> 2;

            A += (B << 5 | B >>> 27) + h(C, D, E) + x[idx++] + Y4;
            C = C << 30 | C >>> 2;
        }


        h1 += A;
        h2 += B;
        h3 += C;
        h4 += D;
        h5 += E;

        //
        // reset start of the buffer.
        //
        xOff = 0;
        for (int i = 0; i < 16; i++) {
            x[i] = 0;
        }
    }

    @Override
    public int length() {
        return 20;
    }

    @Override
    public int blockLength() {
        return 64;
    }

    @Override
    public TlsHash duplicate() {
        return new SHA1Hash();
    }
}
