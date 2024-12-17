package it.auties.leap.tls.hash;

import java.nio.ByteBuffer;
import java.util.Arrays;

public final class SM3Digest implements TlsHashType {
    private static final int BLOCK_LENGTH = 4;
    private static final int[] T = {2043430169, -208106958, -416213915, -832427829, -1664855657, 965255983, 1930511966, -433943364, -867886727, -1735773453, 823420391, 1646840782, -1001285732, -2002571463, 289824371, 579648742, -1651869049, 991229199, 1982458398, -330050500, -660100999, -1320201997, 1654563303, -985840690, -1971681379, 351604539, 703209078, 1406418156, -1482130984, 1330705329, -1633556638, 1027854021, 2055708042, -183551212, -367102423, -734204845, -1468409689, 1358147919, -1578671458, 1137624381, -2019718534, 255530229, 511060458, 1022120916, 2044241832, -206483632, -412967263, -825934525, -1651869049, 991229199, 1982458398, -330050500, -660100999, -1320201997, 1654563303, -985840690, -1971681379, 351604539, 703209078, 1406418156, -1482130984, 1330705329, -1633556638, 1027854021};

    private final byte[] xBuf;
    private int bufferOffset;
    private long byteCount;
    private final int[] v;
    private final int[] inwords;
    private int xOff;
    private final int[] w;

    public SM3Digest() {
        xBuf = new byte[BLOCK_LENGTH];
        v = new int[8];
        inwords = new int[16];
        w = new int[68];
        reset();
    }

    private SM3Digest(SM3Digest other) {
        this.xBuf = other.xBuf.clone();
        this.bufferOffset = other.bufferOffset;
        this.byteCount = other.byteCount;
        this.v = other.v.clone();
        this.inwords = other.inwords.clone();
        this.xOff = other.xOff;
        this.w = other.w.clone();
    }

    @Override
    public void update(byte in) {
        xBuf[bufferOffset++] = in;

        if (bufferOffset == xBuf.length) {
            processWord(xBuf, 0);
            bufferOffset = 0;
        }

        byteCount++;
    }

    @Override
    public void update(byte[] in, int inOff, int len) {
        len = Math.max(0, len);

        int i = 0;
        if (bufferOffset != 0) {
            while (i < len) {
                xBuf[bufferOffset++] = in[inOff + i++];
                if (bufferOffset == 4) {
                    processWord(xBuf, 0);
                    bufferOffset = 0;
                    break;
                }
            }
        }
        int limit = len - 3;
        for (; i < limit; i += 4) {
            processWord(in, inOff + i);
        }

        while (i < len) {
            xBuf[bufferOffset++] = in[inOff + i++];
        }

        byteCount += len;
    }

    @Override
    public void update(ByteBuffer input) {
        var len = input.remaining();
        var inOff = input.position();

        int i = 0;
        if (bufferOffset != 0) {
            while (i < len) {
                xBuf[bufferOffset++] = input.get(inOff + i++);
                if (bufferOffset == 4) {
                    processWord(xBuf, 0);
                    bufferOffset = 0;
                    break;
                }
            }
        }
        int limit = len - 3;
        for (; i < limit; i += 4) {
            processWord(input, inOff + i);
        }

        while (i < len) {
            xBuf[bufferOffset++] = input.get(inOff + i++);
        }

        byteCount += len;
    }

    @Override
    public int digest(byte[] buf, int offset, int length, boolean reset) {
        if (reset) {
            long bitLength = (byteCount << 3);

            update((byte) 128);

            while (bufferOffset != 0) {
                update((byte) 0);
            }

            processLength(bitLength);

            processBlock();

            intToBigEndian(v, buf, offset, length);

            reset();

            return length;
        } else {
            var digest = new SM3Digest(this);
            return digest.digest(buf, offset, length, true);
        }
    }

    @Override
    public void reset() {
        byteCount = 0;

        bufferOffset = 0;
        Arrays.fill(xBuf, (byte) 0);

        this.v[0] = 0x7380166F;
        this.v[1] = 0x4914B2B9;
        this.v[2] = 0x172442D7;
        this.v[3] = 0xDA8A0600;
        this.v[4] = 0xA96F30BC;
        this.v[5] = 0x163138AA;
        this.v[6] = 0xE38DEE4D;
        this.v[7] = 0xB0FB0E4E;

        this.xOff = 0;
    }

    @Override
    public TlsHashType type() {
        return TlsHashType.SM3;
    }

    private void processWord(byte[] in, int inOff) {
        inwords[xOff++] = bigEndianToInt(in, inOff);
        if (this.xOff >= 16) {
            processBlock();
        }
    }

    private void processWord(ByteBuffer in, int inOff) {
        inwords[xOff++] = bigEndianToInt(in, inOff);
        if (this.xOff >= 16) {
            processBlock();
        }
    }

    private void processLength(long bitLength) {
        if (this.xOff > 14) {
            this.inwords[this.xOff] = 0;
            ++this.xOff;

            processBlock();
        }
        while (this.xOff < 14) {
            this.inwords[this.xOff] = 0;
            ++this.xOff;
        }
        this.inwords[this.xOff++] = (int) (bitLength >>> 32);
        this.inwords[this.xOff++] = (int) (bitLength);
    }

    private int P0(int x) {
        int r9 = ((x << 9) | (x >>> (32 - 9)));
        int r17 = ((x << 17) | (x >>> (32 - 17)));
        return (x ^ r9 ^ r17);
    }

    private int P1(int x) {
        int r15 = ((x << 15) | (x >>> (32 - 15)));
        int r23 = ((x << 23) | (x >>> (32 - 23)));
        return (x ^ r15 ^ r23);
    }

    private int FF0(int x, int y, int z) {
        return (x ^ y ^ z);
    }

    private int FF1(int x, int y, int z) {
        return ((x & y) | (x & z) | (y & z));
    }

    private int GG0(int x, int y, int z) {
        return (x ^ y ^ z);
    }

    private int GG1(int x, int y, int z) {
        return ((x & y) | ((~x) & z));
    }

    private void processBlock() {
        System.arraycopy(this.inwords, 0, this.w, 0, 16);

        for (int j = 16; j < 68; ++j) {
            int wj3 = this.w[j - 3];
            int r15 = ((wj3 << 15) | (wj3 >>> (32 - 15)));
            int wj13 = this.w[j - 13];
            int r7 = ((wj13 << 7) | (wj13 >>> (32 - 7)));
            this.w[j] = P1(this.w[j - 16] ^ this.w[j - 9] ^ r15) ^ r7 ^ this.w[j - 6];
        }

        int A = this.v[0];
        int B = this.v[1];
        int C = this.v[2];
        int D = this.v[3];
        int E = this.v[4];
        int F = this.v[5];
        int G = this.v[6];
        int H = this.v[7];


        for (int j = 0; j < 16; ++j) {
            int a12 = ((A << 12) | (A >>> (32 - 12)));
            int s1_ = a12 + E + T[j];
            int SS1 = ((s1_ << 7) | (s1_ >>> (32 - 7)));
            int SS2 = SS1 ^ a12;
            int Wj = w[j];
            int W1j = Wj ^ w[j + 4];
            int TT1 = FF0(A, B, C) + D + SS2 + W1j;
            int TT2 = GG0(E, F, G) + H + SS1 + Wj;
            D = C;
            C = ((B << 9) | (B >>> (32 - 9)));
            B = A;
            A = TT1;
            H = G;
            G = ((F << 19) | (F >>> (32 - 19)));
            F = E;
            E = P0(TT2);
        }

        for (int j = 16; j < 64; ++j) {
            int a12 = ((A << 12) | (A >>> (32 - 12)));
            int s1_ = a12 + E + T[j];
            int SS1 = ((s1_ << 7) | (s1_ >>> (32 - 7)));
            int SS2 = SS1 ^ a12;
            int Wj = w[j];
            int W1j = Wj ^ w[j + 4];
            int TT1 = FF1(A, B, C) + D + SS2 + W1j;
            int TT2 = GG1(E, F, G) + H + SS1 + Wj;
            D = C;
            C = ((B << 9) | (B >>> (32 - 9)));
            B = A;
            A = TT1;
            H = G;
            G = ((F << 19) | (F >>> (32 - 19)));
            F = E;
            E = P0(TT2);
        }

        this.v[0] ^= A;
        this.v[1] ^= B;
        this.v[2] ^= C;
        this.v[3] ^= D;
        this.v[4] ^= E;
        this.v[5] ^= F;
        this.v[6] ^= G;
        this.v[7] ^= H;

        this.xOff = 0;
    }

    @Override
    public int length() {
        return 32;
    }

    @Override
    public int blockLength() {
        return 64;
    }
}
