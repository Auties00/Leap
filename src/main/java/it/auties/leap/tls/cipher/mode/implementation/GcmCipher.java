package it.auties.leap.tls.cipher.mode.implementation;

import it.auties.leap.tls.cipher.engine.TlsCipherEngine;
import it.auties.leap.tls.cipher.mode.TlsCipher;
import it.auties.leap.tls.cipher.mode.TlsCipherFactory;
import it.auties.leap.tls.cipher.mode.TlsCipherWithEngineFactory;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.cipher.exchange.TlsExchangeMac;
import it.auties.leap.tls.message.TlsMessageMetadata;
import it.auties.leap.tls.util.BufferUtils;
import org.bouncycastle.math.raw.Interleave;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Longs;

import java.nio.ByteBuffer;


public final class GcmCipher extends TlsCipher.Block {
    private static final TlsCipherFactory FACTORY = (factory) -> new TlsCipherWithEngineFactory() {
        @Override
        public TlsCipher newCipher(boolean forEncryption, byte[] key, byte[] fixedIv, TlsExchangeMac authenticator) {
            var engine = factory.newCipherEngine(true, key);
            return new GcmCipher(engine, forEncryption, fixedIv, authenticator);
        }

        @Override
        public int ivLength() {
            return 12;
        }

        @Override
        public int fixedIvLength() {
            return 4;
        }

        @Override
        public int tagLength() {
            return factory.blockLength();
        }
    };

    private final Tables4kGCMMultiplier multiplier;
    private BasicGCMExponentiator exp;

    private final byte[] H;
    private byte[] J0;

    private final byte[] bufBlock;
    private byte[] macBlock;
    private byte[] S, S_at, S_atPre;
    private byte[] counter;
    private int blocksRemaining;
    private int bufOff;
    private long totalLength;
    private byte[] atBlock;
    private int atBlockPos;
    private long atLength;
    private long atLengthPre;

    // Can't rely on the engine's value as that is always set on encryption mode
    private final boolean forEncryption;

    private GcmCipher(TlsCipherEngine engine, boolean forEncryption, byte[] fixedIv, TlsExchangeMac authenticator) {
        super(engine, fixedIv, authenticator);
        this.forEncryption = forEncryption;
        this.multiplier = new Tables4kGCMMultiplier();
        var bufLength = this.forEncryption ? engine().blockLength() : (engine().blockLength() + tagLength());
        this.bufBlock = new byte[bufLength];
        this.H = new byte[engine().blockLength()];
        engine.cipher(ByteBuffer.wrap(H), ByteBuffer.wrap(H));
        multiplier.init(H);
        this.S = new byte[engine().blockLength()];
        this.S_at = new byte[engine().blockLength()];
        this.S_atPre = new byte[engine().blockLength()];
        this.atBlock = new byte[engine().blockLength()];
        this.atBlockPos = 0;
        this.atLength = 0;
        this.atLengthPre = 0;
        this.blocksRemaining = -2;      // page 8, len(P) <= 2^39 - 256, 1 block used by tag but done on J0
        this.bufOff = 0;
        this.totalLength = 0;
    }


    public static TlsCipherFactory factory() {
        return FACTORY;
    }


    public void processAADBytes(byte[] in, int inOff, int len) {
        var BLOCK_SIZE = engine().blockLength();

        if (atBlockPos > 0) {
            int available = BLOCK_SIZE - atBlockPos;
            if (len < available) {
                System.arraycopy(in, inOff, atBlock, atBlockPos, len);
                atBlockPos += len;
                return;
            }

            System.arraycopy(in, inOff, atBlock, atBlockPos, available);
            gHASHBlock(S_at, atBlock);
            atLength += BLOCK_SIZE;
            inOff += available;
            len -= available;
            //atBlockPos = 0;
        }

        int inLimit = inOff + len - BLOCK_SIZE;

        while (inOff <= inLimit) {
            gHASHBlock(S_at, in, inOff);
            atLength += BLOCK_SIZE;
            inOff += BLOCK_SIZE;
        }

        atBlockPos = BLOCK_SIZE + inLimit - inOff;
        System.arraycopy(in, inOff, atBlock, 0, atBlockPos);
    }

    @Override
    public void encrypt(byte contentType, ByteBuffer input, ByteBuffer output) {
        var iv = new byte[ivLength()];
        System.arraycopy(fixedIv, 0, iv, 0, fixedIv.length);
        var nonce = authenticator.sequenceNumber();
        System.arraycopy(nonce, 0, iv, fixedIv.length, nonce.length);
        output.put(output.position() - nonce.length, nonce);

        this.J0 = new byte[engine().blockLength()];
        System.arraycopy(iv, 0, J0, 0, iv.length);
        this.J0[J0.length - 1] = 0x01;
        this.counter = Arrays.clone(J0);

        var aad = authenticator.createAuthenticationBlock(contentType, input.remaining() - (forEncryption ? 0 : tagLength()), null);
        processAADBytes(aad, 0, aad.length);

        var resultLen = processBytes(input.array(), input.position(), input.remaining(), output.array(), output.position());
        resultLen += doFinal(output.array(), output.position() + resultLen);
        output.position(output.position() - (forEncryption ? dynamicIvLength(): 0));
        output.limit(output.position() + (forEncryption ? dynamicIvLength(): 0) + resultLen);
    }

    @Override
    public ByteBuffer decrypt(TlsContext context, TlsMessageMetadata metadata, ByteBuffer input) {
        var output = input.duplicate()
                .limit(input.capacity());

        var iv = new byte[ivLength()];
        System.arraycopy(fixedIv, 0, iv, 0, fixedIv.length);
        input.get(iv, fixedIv.length, dynamicIvLength());

        this.J0 = new byte[engine().blockLength()];
        System.arraycopy(iv, 0, J0, 0, iv.length);
        this.J0[J0.length - 1] = 0x01;
        this.counter = Arrays.clone(J0);

        var aad = authenticator.createAuthenticationBlock(metadata.contentType().id(), input.remaining() - (forEncryption ? 0 : tagLength()), null);
        processAADBytes(aad, 0, aad.length);

        var resultLen = processBytes(input.array(), input.position(), input.remaining(), output.array(), output.position());
        resultLen += doFinal(output.array(), output.position() + resultLen);

        output.position(output.position() - (forEncryption ? dynamicIvLength(): 0));
        output.limit(output.position() + (forEncryption ? dynamicIvLength(): 0) + resultLen);

        return output;
    }

    public int doFinal(byte[] out, int outOff) {
        var macSize = tagLength();
        var BLOCK_SIZE = engine().blockLength();

        if (totalLength == 0) {
            initCipher();
        }

        int extra = bufOff;
        if (!forEncryption) {
            extra -= macSize;
        }

        if (extra > 0) {
            processPartial(bufBlock, 0, extra, out, outOff);
        }

        atLength += atBlockPos;

        if (atLength > atLengthPre) {
            /*
             *  Some AAD was sent after the cipher started. We determine the difference b/w the hash value
             *  we actually used when the cipher started (S_atPre) and the final hash value calculated (S_at).
             *  Then we carry this difference forward by multiplying by H^c, where c is the number of (full or
             *  partial) cipher-text blocks produced, and adjust the current hash.
             */

            // Finish hash for partial AAD block
            if (atBlockPos > 0) {
                gHASHPartial(S_at, atBlock, 0, atBlockPos);
            }

            // Find the difference between the AAD hashes
            if (atLengthPre > 0) {
                GCMUtil.xor(S_at, S_atPre);
            }

            // Number of cipher-text blocks produced
            long c = ((totalLength * 8) + 127) >>> 7;

            // Calculate the adjustment factor
            byte[] H_c = new byte[16];
            if (exp == null) {
                exp = new BasicGCMExponentiator();
                exp.init(H);
            }
            exp.exponentiateX(c, H_c);

            // Carry the difference forward
            GCMUtil.multiply(S_at, H_c);

            // Adjust the current hash
            GCMUtil.xor(S, S_at);
        }

        // Final gHASH
        byte[] X = new byte[BLOCK_SIZE];
        BufferUtils.writeBigEndianInt64(atLength * 8, X, 0);
        BufferUtils.writeBigEndianInt64(totalLength * 8, X, 8);

        gHASHBlock(S, X);

        // T = MSBt(GCTRk(J0,S))
        byte[] tag = new byte[BLOCK_SIZE];
        engine().cipher(ByteBuffer.wrap(J0), ByteBuffer.wrap(tag));
        GCMUtil.xor(tag, S);

        int resultLen = extra;

        // We place into macBlock our calculated value for T
        this.macBlock = new byte[macSize];
        System.arraycopy(tag, 0, macBlock, 0, macSize);

        if (forEncryption) {
            // Append T to the message
            System.arraycopy(macBlock, 0, out, outOff + bufOff, macSize);
            resultLen += macSize;
        } else {
            // Retrieve the T value from the message and compare to calculated one
            byte[] msgMac = new byte[macSize];
            System.arraycopy(bufBlock, extra, msgMac, 0, macSize);
            if (!Arrays.constantTimeAreEqual(this.macBlock, msgMac)) {
                throw new RuntimeException("mac check in GCM failed");
            }
        }

        reset(false);

        return resultLen;
    }

    public int processBytes(byte[] in, int inOff, int len, byte[] out, int outOff) {
        int resultLen = 0;
        var BLOCK_SIZE = engine().blockLength();

        if (forEncryption) {
            if (bufOff > 0) {
                int available = BLOCK_SIZE - bufOff;
                if (len < available) {
                    System.arraycopy(in, inOff, bufBlock, bufOff, len);
                    bufOff += len;
                    return 0;
                }

                System.arraycopy(in, inOff, bufBlock, bufOff, available);
                encryptBlock(bufBlock, 0, out, outOff);
                inOff += available;
                len -= available;
                resultLen = BLOCK_SIZE;
                //bufOff = 0;
            }

            int inLimit = inOff + len - BLOCK_SIZE;

            while (inOff <= inLimit) {
                encryptBlock(in, inOff, out, outOff + resultLen);
                inOff += BLOCK_SIZE;
                resultLen += BLOCK_SIZE;
            }

            bufOff = BLOCK_SIZE + inLimit - inOff;
            System.arraycopy(in, inOff, bufBlock, 0, bufOff);
        } else {
            int available = bufBlock.length - bufOff;
            if (len < available) {
                System.arraycopy(in, inOff, bufBlock, bufOff, len);
                bufOff += len;
                return 0;
            }

            if (bufOff >= BLOCK_SIZE) {
                decryptBlock(bufBlock, 0, out, outOff);
                System.arraycopy(bufBlock, BLOCK_SIZE, bufBlock, 0, bufOff -= BLOCK_SIZE);
                resultLen = BLOCK_SIZE;

                available += BLOCK_SIZE;
                if (len < available) {
                    System.arraycopy(in, inOff, bufBlock, bufOff, len);
                    bufOff += len;
                    return resultLen;
                }
            }

            int inLimit = inOff + len - bufBlock.length;

            available = BLOCK_SIZE - bufOff;
            System.arraycopy(in, inOff, bufBlock, bufOff, available);
            decryptBlock(bufBlock, 0, out, outOff + resultLen);
            inOff += available;
            resultLen += BLOCK_SIZE;
            //bufOff = 0;

            while (inOff <= inLimit) {
                decryptBlock(in, inOff, out, outOff + resultLen);
                inOff += BLOCK_SIZE;
                resultLen += BLOCK_SIZE;
            }

            bufOff = bufBlock.length + inLimit - inOff;
            System.arraycopy(in, inOff, bufBlock, 0, bufOff);
        }

        return resultLen;
    }

    private void initCipher() {
        if (atLength > 0) {
            System.arraycopy(S_at, 0, S_atPre, 0, engine().blockLength());
            atLengthPre = atLength;
        }

        // Finish hash for partial AAD block
        if (atBlockPos > 0) {
            gHASHPartial(S_atPre, atBlock, 0, atBlockPos);
            atLengthPre += atBlockPos;
        }

        if (atLengthPre > 0) {
            System.arraycopy(S_atPre, 0, S, 0, engine().blockLength());
        }
    }

    private void reset(boolean clearMac) {
        // note: we do not reset the nonce.

        S = new byte[engine().blockLength()];
        S_at = new byte[engine().blockLength()];
        S_atPre = new byte[engine().blockLength()];
        atBlock = new byte[engine().blockLength()];
        atBlockPos = 0;
        atLength = 0;
        atLengthPre = 0;
        counter = Arrays.clone(J0);
        blocksRemaining = -2;
        bufOff = 0;
        totalLength = 0;

        if (bufBlock != null) {
            Arrays.fill(bufBlock, (byte) 0);
        }

        if (clearMac) {
            macBlock = null;
        }
    }

    private void decryptBlock(byte[] buf, int bufOff, byte[] out, int outOff) {
        if ((out.length - outOff) < engine().blockLength()) {
            throw new RuntimeException("Output buffer too short");
        }
        if (totalLength == 0) {
            initCipher();
        }

        byte[] ctrBlock = new byte[engine().blockLength()];
        getNextCTRBlock(ctrBlock);

        gHASHBlock(S, buf, bufOff);
        GCMUtil.xor(ctrBlock, 0, buf, bufOff, out, outOff);

        totalLength += engine().blockLength();
    }

    private void encryptBlock(byte[] buf, int bufOff, byte[] out, int outOff) {
        if ((out.length - outOff) < engine().blockLength()) {
            throw new RuntimeException("Output buffer too short");
        }
        if (totalLength == 0) {
            initCipher();
        }

        byte[] ctrBlock = new byte[engine().blockLength()];

        getNextCTRBlock(ctrBlock);
        GCMUtil.xor(ctrBlock, buf, bufOff);
        gHASHBlock(S, ctrBlock);
        System.arraycopy(ctrBlock, 0, out, outOff, engine().blockLength());

        totalLength += engine().blockLength();
    }

    private void processPartial(byte[] buf, int off, int len, byte[] out, int outOff) {
        byte[] ctrBlock = new byte[engine().blockLength()];
        getNextCTRBlock(ctrBlock);

        if (forEncryption) {
            GCMUtil.xor(buf, off, ctrBlock, 0, len);
            gHASHPartial(S, buf, off, len);
        } else {
            gHASHPartial(S, buf, off, len);
            GCMUtil.xor(buf, off, ctrBlock, 0, len);
        }

        System.arraycopy(buf, off, out, outOff, len);
        totalLength += len;
    }

    private void gHASHBlock(byte[] Y, byte[] b) {
        GCMUtil.xor(Y, b);
        multiplier.multiplyH(Y);
    }

    private void gHASHBlock(byte[] Y, byte[] b, int off) {
        GCMUtil.xor(Y, b, off);
        multiplier.multiplyH(Y);
    }

    private void gHASHPartial(byte[] Y, byte[] b, int off, int len) {
        GCMUtil.xor(Y, b, off, len);
        multiplier.multiplyH(Y);
    }

    private void getNextCTRBlock(byte[] block) {
        if (blocksRemaining == 0) {
            throw new IllegalStateException("Attempt to process too many blocks");
        }
        blocksRemaining--;

        int c = 1;
        c += counter[15] & 0xFF;
        counter[15] = (byte) c;
        c >>>= 8;
        c += counter[14] & 0xFF;
        counter[14] = (byte) c;
        c >>>= 8;
        c += counter[13] & 0xFF;
        counter[13] = (byte) c;
        c >>>= 8;
        c += counter[12] & 0xFF;
        counter[12] = (byte) c;

        engine.cipher(ByteBuffer.wrap(counter), ByteBuffer.wrap(block));
    }

    @Override
    public int ivLength() {
        return 12;
    }

    @Override
    public int fixedIvLength() {
        return 4;
    }

    @Override
    public int tagLength() {
        return engine().blockLength();
    }

    private static final class BasicGCMExponentiator {
        private long[] x;

        public void init(byte[] x) {
            this.x = GCMUtil.asLongs(x);
        }

        public void exponentiateX(long pow, byte[] output) {
            // Initial value is little-endian 1
            long[] y = GCMUtil.oneAsLongs();

            if (pow > 0) {
                long[] powX = new long[GCMUtil.SIZE_LONGS];
                GCMUtil.copy(x, powX);

                do {
                    if ((pow & 1L) != 0) {
                        GCMUtil.multiply(y, powX);
                    }
                    GCMUtil.square(powX, powX);
                    pow >>>= 1;
                } while (pow > 0);
            }

            GCMUtil.asBytes(y, output);
        }
    }

    private static final class Tables4kGCMMultiplier {
        private byte[] H;
        private long[][] T;

        public void init(byte[] H) {
            if (T == null) {
                T = new long[256][2];
            } else if (0 != GCMUtil.areEqual(this.H, H)) {
                return;
            }

            this.H = new byte[GCMUtil.SIZE_BYTES];
            GCMUtil.copy(H, this.H);

            // T[0] = 0

            // T[1] = H.p^7
            GCMUtil.asLongs(this.H, T[1]);
            GCMUtil.multiplyP7(T[1], T[1]);

            for (int n = 2; n < 256; n += 2) {
                // T[2.n] = T[n].p^-1
                GCMUtil.divideP(T[n >> 1], T[n]);

                // T[2.n + 1] = T[2.n] + T[1]
                GCMUtil.xor(T[n], T[1], T[n + 1]);
            }
        }

        public void multiplyH(byte[] x) {
            long[] t = T[x[15] & 0xFF];
            long z0 = t[0], z1 = t[1];

            for (int i = 14; i >= 0; --i) {
                t = T[x[i] & 0xFF];

                long c = z1 << 56;
                z1 = t[1] ^ ((z1 >>> 8) | (z0 << 56));
                z0 = t[0] ^ (z0 >>> 8) ^ c ^ (c >>> 1) ^ (c >>> 2) ^ (c >>> 7);
            }

            BufferUtils.writeBigEndianInt64(z0, x, 0);
            BufferUtils.writeBigEndianInt64(z1, x, 8);
        }
    }

    private static final class GCMUtil {
        public static final int SIZE_BYTES = 16;
        public static final int SIZE_LONGS = 2;

        private static final int E1 = 0xe1000000;
        private static final long E1L = (E1 & 0xFFFFFFFFL) << 32;

        public static long[] oneAsLongs() {
            long[] tmp = new long[SIZE_LONGS];
            tmp[0] = 1L << 63;
            return tmp;
        }

        public static byte areEqual(byte[] x, byte[] y) {
            int d = 0;
            for (int i = 0; i < SIZE_BYTES; ++i) {
                d |= x[i] ^ y[i];
            }
            d = (d >>> 1) | (d & 1);
            return (byte) ((d - 1) >> 31);
        }

        public static void asBytes(long[] x, byte[] z) {
            for (int i = 0; i < SIZE_LONGS; ++i) {
                BufferUtils.writeBigEndianInt64(x[i], z, i * 8);
            }
        }

        public static long[] asLongs(byte[] x) {
            long[] z = new long[SIZE_LONGS];
            asLongs(x, z);
            return z;
        }

        public static void asLongs(byte[] x, long[] z) {
            for (int i = 0; i < SIZE_LONGS; ++i) {
                z[i] = BufferUtils.readBigEndianInt64(x, i * 8);
            }
        }

        public static void copy(byte[] x, byte[] z) {
            for (int i = 0; i < SIZE_BYTES; ++i) {
                z[i] = x[i];
            }
        }

        public static void copy(long[] x, long[] z) {
            z[0] = x[0];
            z[1] = x[1];
        }

        public static void divideP(long[] x, long[] z) {
            long x0 = x[0], x1 = x[1];
            long m = x0 >> 63;
            x0 ^= (m & E1L);
            z[0] = (x0 << 1) | (x1 >>> 63);
            z[1] = (x1 << 1) | -m;
        }

        public static void multiply(byte[] x, byte[] y) {
            long[] t1 = asLongs(x);
            long[] t2 = asLongs(y);
            multiply(t1, t2);
            asBytes(t1, x);
        }

        public static void multiply(long[] x, long[] y) {
//        long x0 = x[0], x1 = x[1];
//        long y0 = y[0], y1 = y[1];
//        long z0 = 0, z1 = 0, z2 = 0;
//
//        for (int j = 0; j < 64; ++j)
//        {
//            long m0 = x0 >> 63; x0 <<= 1;
//            z0 ^= (y0 & m0);
//            z1 ^= (y1 & m0);
//
//            long m1 = x1 >> 63; x1 <<= 1;
//            z1 ^= (y0 & m1);
//            z2 ^= (y1 & m1);
//
//            long c = (y1 << 63) >> 8;
//            y1 = (y1 >>> 1) | (y0 << 63);
//            y0 = (y0 >>> 1) ^ (c & E1L);
//        }
//
//        z0 ^= z2 ^ (z2 >>>  1) ^ (z2 >>>  2) ^ (z2 >>>  7);
//        z1 ^=      (z2 <<  63) ^ (z2 <<  62) ^ (z2 <<  57);
//
//        x[0] = z0;
//        x[1] = z1;

            /*
             * "Three-way recursion" as described in "Batch binary Edwards", Daniel J. Bernstein.
             *
             * Without access to the high part of a 64x64 product x * y, we use a bit reversal to calculate it:
             *     rev(x) * rev(y) == rev((x * y) << 1)
             */

            long x0 = x[0], x1 = x[1];
            long y0 = y[0], y1 = y[1];
            long x0r = Longs.reverse(x0), x1r = Longs.reverse(x1);
            long y0r = Longs.reverse(y0), y1r = Longs.reverse(y1);

            long h0 = Longs.reverse(implMul64(x0r, y0r));
            long h1 = implMul64(x0, y0) << 1;
            long h2 = Longs.reverse(implMul64(x1r, y1r));
            long h3 = implMul64(x1, y1) << 1;
            long h4 = Longs.reverse(implMul64(x0r ^ x1r, y0r ^ y1r));
            long h5 = implMul64(x0 ^ x1, y0 ^ y1) << 1;

            long z0 = h0;
            long z1 = h1 ^ h0 ^ h2 ^ h4;
            long z2 = h2 ^ h1 ^ h3 ^ h5;
            long z3 = h3;

            z1 ^= z3 ^ (z3 >>> 1) ^ (z3 >>> 2) ^ (z3 >>> 7);
//      z2 ^=      (z3 <<  63) ^ (z3 <<  62) ^ (z3 <<  57);
            z2 ^= (z3 << 62) ^ (z3 << 57);

            z0 ^= z2 ^ (z2 >>> 1) ^ (z2 >>> 2) ^ (z2 >>> 7);
            z1 ^= (z2 << 63) ^ (z2 << 62) ^ (z2 << 57);

            x[0] = z0;
            x[1] = z1;
        }

        public static void multiplyP7(long[] x, long[] z) {
            long x0 = x[0], x1 = x[1];
            long c = x1 << 57;
            z[0] = (x0 >>> 7) ^ c ^ (c >>> 1) ^ (c >>> 2) ^ (c >>> 7);
            z[1] = (x1 >>> 7) | (x0 << 57);
        }

        public static void square(long[] x, long[] z) {
            long[] t = new long[SIZE_LONGS * 2];
            Interleave.expand64To128Rev(x[0], t, 0);
            Interleave.expand64To128Rev(x[1], t, 2);

            long z0 = t[0], z1 = t[1], z2 = t[2], z3 = t[3];

            z1 ^= z3 ^ (z3 >>> 1) ^ (z3 >>> 2) ^ (z3 >>> 7);
            z2 ^= (z3 << 63) ^ (z3 << 62) ^ (z3 << 57);

            z0 ^= z2 ^ (z2 >>> 1) ^ (z2 >>> 2) ^ (z2 >>> 7);
            z1 ^= (z2 << 63) ^ (z2 << 62) ^ (z2 << 57);

            z[0] = z0;
            z[1] = z1;
        }

        public static void xor(byte[] x, byte[] y) {
            int i = 0;
            do {
                x[i] ^= y[i];
                ++i;
                x[i] ^= y[i];
                ++i;
                x[i] ^= y[i];
                ++i;
                x[i] ^= y[i];
                ++i;
            } while (i < SIZE_BYTES);
        }

        public static void xor(byte[] x, byte[] y, int yOff) {
            int i = 0;
            do {
                x[i] ^= y[yOff + i];
                ++i;
                x[i] ^= y[yOff + i];
                ++i;
                x[i] ^= y[yOff + i];
                ++i;
                x[i] ^= y[yOff + i];
                ++i;
            } while (i < SIZE_BYTES);
        }

        public static void xor(byte[] x, int xOff, byte[] y, int yOff, byte[] z, int zOff) {
            int i = 0;
            do {
                z[zOff + i] = (byte) (x[xOff + i] ^ y[yOff + i]);
                ++i;
                z[zOff + i] = (byte) (x[xOff + i] ^ y[yOff + i]);
                ++i;
                z[zOff + i] = (byte) (x[xOff + i] ^ y[yOff + i]);
                ++i;
                z[zOff + i] = (byte) (x[xOff + i] ^ y[yOff + i]);
                ++i;
            } while (i < SIZE_BYTES);
        }

        public static void xor(byte[] x, byte[] y, int yOff, int yLen) {
            while (--yLen >= 0) {
                x[yLen] ^= y[yOff + yLen];
            }
        }

        public static void xor(byte[] x, int xOff, byte[] y, int yOff, int len) {
            while (--len >= 0) {
                x[xOff + len] ^= y[yOff + len];
            }
        }

        public static void xor(long[] x, long[] y, long[] z) {
            z[0] = x[0] ^ y[0];
            z[1] = x[1] ^ y[1];
        }

        private static long implMul64(long x, long y) {
            long x0 = x & 0x1111111111111111L;
            long x1 = x & 0x2222222222222222L;
            long x2 = x & 0x4444444444444444L;
            long x3 = x & 0x8888888888888888L;

            long y0 = y & 0x1111111111111111L;
            long y1 = y & 0x2222222222222222L;
            long y2 = y & 0x4444444444444444L;
            long y3 = y & 0x8888888888888888L;

            long z0 = (x0 * y0) ^ (x1 * y3) ^ (x2 * y2) ^ (x3 * y1);
            long z1 = (x0 * y1) ^ (x1 * y0) ^ (x2 * y3) ^ (x3 * y2);
            long z2 = (x0 * y2) ^ (x1 * y1) ^ (x2 * y0) ^ (x3 * y3);
            long z3 = (x0 * y3) ^ (x1 * y2) ^ (x2 * y1) ^ (x3 * y0);

            z0 &= 0x1111111111111111L;
            z1 &= 0x2222222222222222L;
            z2 &= 0x4444444444444444L;
            z3 &= 0x8888888888888888L;

            return z0 | z1 | z2 | z3;
        }
    }
}
