package it.auties.leap.tls.crypto.cipher.mode;

import it.auties.leap.tls.TlsBuffer;
import it.auties.leap.tls.crypto.cipher.engine.TlsCipherEngine;

import java.nio.ByteBuffer;
import java.util.Arrays;

final class ChaCha20Poly1305Mode implements TlsCipherMode.Stream, TlsCipherMode.AEAD {
    private static final int BUF_SIZE = 64;
    private static final int MAC_SIZE = 16;
    private static final byte[] ZEROES = new byte[MAC_SIZE - 1];

    private static final long DATA_LIMIT = ((1L << 32) - 1) * 64;

    private final TlsCipherEngine.Block chacha20;
    private final Poly1305 poly1305;

    private final byte[] nonce;
    private final ByteBuffer buf;
    private final byte[] mac = new byte[MAC_SIZE];
    private final byte[] initialAAD;

    private long aadCount;
    private long dataCount;
    private int state;

    public ChaCha20Poly1305Mode(TlsCipherEngine.Block cipher, byte[] iv, byte[] aad) {
        this.chacha20 = cipher;
        this.poly1305 = new Poly1305(cipher.key());
        this.nonce = iv;
        this.buf = ByteBuffer.allocate(BUF_SIZE + MAC_SIZE);
        this.initialAAD = aad;
        this.state = cipher.forEncryption() ? State.ENC_INIT : State.DEC_INIT;
        reset(true, false);
    }

    @Override
    public void update(ByteBuffer input, ByteBuffer output, boolean last) {
        if (last) {
            doFinal(input, output);
        } else {
            processBytes(input, output);
        }
    }

    public void processBytes(ByteBuffer input, ByteBuffer output) {
        checkData();

        int resultLen = 0;

        switch (state) {
            case State.DEC_DATA -> {
                while (input.hasRemaining()) {
                    buf.put(input);
                    if (!buf.hasRemaining()) {
                        poly1305.update(buf);
                        processData(buf, output);
                        buf.clear();
                        buf.put()
                        System.arraycopy(buf, BUF_SIZE, buf, 0, MAC_SIZE);
                        this.bufPos = MAC_SIZE;
                        resultLen += BUF_SIZE;
                    }
                }
            }
            case State.ENC_DATA -> {
                if (bufPos != 0) {
                    while (len > 0) {
                        --len;
                        buf[bufPos] = in[inOff++];
                        if (++bufPos == BUF_SIZE) {
                            processData(buf, 0, BUF_SIZE, out, outOff);
                            poly1305.update(out, outOff, BUF_SIZE);
                            this.bufPos = 0;
                            resultLen = BUF_SIZE;
                            break;
                        }
                    }
                }

                while (len >= BUF_SIZE) {
                    processData(in, inOff, BUF_SIZE, out, outOff + resultLen);
                    poly1305.update(out, outOff + resultLen, BUF_SIZE);
                    inOff += BUF_SIZE;
                    len -= BUF_SIZE;
                    resultLen += BUF_SIZE;
                }

                if (len > 0) {
                    System.arraycopy(in, inOff, buf, 0, len);
                    this.bufPos = len;
                }
            }
            default -> throw new IllegalStateException();
        }
    }

    public void doFinal(ByteBuffer output) {
        checkData();

        Arrays.fill(mac, (byte) 0);

        switch (state) {
            case State.DEC_DATA -> {
                var resultLen = buf.position() - MAC_SIZE;
                if (resultLen > 0) {
                    poly1305.update(buf.position(0).limit(resultLen));
                    processData(buf, output);
                }

                finishData(State.DEC_FINAL);

                if (!Arrays.constantTimeAreEqual(MAC_SIZE, mac, 0, buf, resultLen)) {
                    throw new InvalidCipherTextException("mac check in ChaCha20Poly1305 failed");
                }

            }
            case State.ENC_DATA -> {
                resultLen = bufPos + MAC_SIZE;

                if (outOff > (out.length - resultLen)) {
                    throw new OutputLengthException("Output buffer too short");
                }

                if (bufPos > 0) {
                    processData(buf, 0, bufPos, out, outOff);
                    poly1305.update(out, outOff, bufPos);
                }

                finishData(State.ENC_FINAL);

                System.arraycopy(mac, 0, out, outOff + bufPos, MAC_SIZE);
            }
            default -> throw new IllegalStateException();
        }

        reset(false, true);
    }

    @Override
    public void reset() {
        reset(true, true);
    }

    private void checkData() {
        switch (state) {
            case State.DEC_INIT, State.DEC_AAD -> finishAAD(State.DEC_DATA);
            case State.ENC_INIT, State.ENC_AAD -> finishAAD(State.ENC_DATA);
            case State.DEC_DATA, State.ENC_DATA -> {
            }
            case State.ENC_FINAL -> throw new IllegalStateException("ChaCha20Poly1305 cannot be reused for encryption");
            default -> throw new IllegalStateException();
        }
    }

    private void finishAAD(int nextState) {
        padMAC(aadCount);

        this.state = nextState;
    }


    private void finishData(int nextState) {
        padMAC(dataCount);

        byte[] lengths = new byte[16];
        Pack.longToLittleEndian(aadCount, lengths, 0);
        Pack.longToLittleEndian(dataCount, lengths, 8);
        poly1305.update(lengths, 0, 16);

        poly1305.doFinal(mac, 0);

        this.state = nextState;
    }

    private long incrementCount(long count, int increment, long limit) {
        if (count + Long.MIN_VALUE > (limit - increment) + Long.MIN_VALUE) {
            throw new IllegalStateException("Limit exceeded");
        }

        return count + increment;
    }

    private void initMAC() {
        byte[] firstBlock = new byte[64];
        try {
            chacha20.processBytes(firstBlock, 0, 64, firstBlock, 0);
            poly1305.init(new KeyParameter(firstBlock, 0, 32));
        } finally {
            Arrays.fill(firstBlock, (byte) 0);
        }
    }

    private void padMAC(long count) {
        int partial = (int) count & (MAC_SIZE - 1);
        if (0 != partial) {
            poly1305.update(ZEROES, 0, MAC_SIZE - partial);
        }
    }

    private void processData(byte[] in, int inOff, int inLen, byte[] out, int outOff) {
        chacha20.processBytes(in, inOff, inLen, out, outOff);

        this.dataCount = incrementCount(dataCount, inLen, DATA_LIMIT);
    }

    private void reset(boolean clearMac, boolean resetCipher) {
        buf.clear();

        if (clearMac) {
            Arrays.fill(mac, (byte) 0);
        }

        this.aadCount = 0L;
        this.dataCount = 0L;
        this.bufPos = 0;

        switch (state) {
            case State.DEC_INIT:
            case State.ENC_INIT:
                break;
            case State.DEC_AAD:
            case State.DEC_DATA:
            case State.DEC_FINAL:
                this.state = State.DEC_INIT;
                break;
            case State.ENC_AAD:
            case State.ENC_DATA:
            case State.ENC_FINAL:
                this.state = State.ENC_FINAL;
                return;
            default:
                throw new IllegalStateException();
        }

        if (resetCipher) {
            chacha20.reset();
        }

        initMAC();

        if (null != initialAAD) {
            this.aadCount = incrementCount(aadCount, initialAAD.length, -1);
            poly1305.update(ByteBuffer.wrap(initialAAD));
        }
    }

    private static final class Poly1305 {
        private static final int BLOCK_SIZE = 16;

        private final byte[] singleByte = new byte[1];

        // Initialised state

        /**
         * Polynomial key
         */
        private int r0, r1, r2, r3, r4;

        /**
         * Precomputed 5 * r[1..4]
         */
        private int s1, s2, s3, s4;

        /**
         * Encrypted nonce
         */
        private int k0, k1, k2, k3;

        // Accumulating state

        /**
         * Current block of buffered input
         */
        private final byte[] currentBlock = new byte[BLOCK_SIZE];

        /**
         * Current offset in input buffer
         */
        private int currentBlockOffset = 0;

        /**
         * Polynomial accumulator
         */
        private int h0, h1, h2, h3, h4;

        /**
         * Constructs a Poly1305 MAC, using a 128 bit block cipher.
         */
        public Poly1305(byte[] key) {
            setKey(key, null);
            reset();
        }

        private void setKey(final byte[] key, final byte[] nonce) {
            if (key.length != 32) {
                throw new IllegalArgumentException("Poly1305 key must be 256 bits.");
            }
            if ((nonce == null || nonce.length != BLOCK_SIZE)) {
                throw new IllegalArgumentException("Poly1305 requires a 128 bit IV.");
            }

            // Extract r portion of key (and "clamp" the values)
            int t0 = TlsBuffer.readLittleEndianInt32(key, 0);
            int t1 = TlsBuffer.readLittleEndianInt32(key, 4);
            int t2 = TlsBuffer.readLittleEndianInt32(key, 8);
            int t3 = TlsBuffer.readLittleEndianInt32(key, 12);

            // NOTE: The masks perform the key "clamping" implicitly
            r0 = t0 & 0x03FFFFFF;
            r1 = ((t0 >>> 26) | (t1 << 6)) & 0x03FFFF03;
            r2 = ((t1 >>> 20) | (t2 << 12)) & 0x03FFC0FF;
            r3 = ((t2 >>> 14) | (t3 << 18)) & 0x03F03FFF;
            r4 = (t3 >>> 8) & 0x000FFFFF;

            // Precompute multipliers
            s1 = r1 * 5;
            s2 = r2 * 5;
            s3 = r3 * 5;
            s4 = r4 * 5;

            final byte[] kBytes;
            final int kOff;

            kBytes = key;
            kOff = BLOCK_SIZE;

            k0 = TlsBuffer.readLittleEndianInt32(kBytes, kOff + 0);
            k1 = TlsBuffer.readLittleEndianInt32(kBytes, kOff + 4);
            k2 = TlsBuffer.readLittleEndianInt32(kBytes, kOff + 8);
            k3 = TlsBuffer.readLittleEndianInt32(kBytes, kOff + 12);
        }

        public void update(ByteBuffer input) {
            int copied = 0;
            int len = input.remaining();
            while (input.hasRemaining()) {
                if (currentBlockOffset == BLOCK_SIZE) {
                    processBlock();
                    currentBlockOffset = 0;
                }

                int toCopy = Math.min((len - copied), BLOCK_SIZE - currentBlockOffset);
                input.get(currentBlock, currentBlockOffset, toCopy);
                copied += toCopy;
                currentBlockOffset += toCopy;
            }
        }

        private void processBlock() {
            if (currentBlockOffset < BLOCK_SIZE) {
                currentBlock[currentBlockOffset] = 1;
                for (int i = currentBlockOffset + 1; i < BLOCK_SIZE; i++) {
                    currentBlock[i] = 0;
                }
            }

            final long t0 = 0xffffffffL & TlsBuffer.readLittleEndianInt32(currentBlock, 0);
            final long t1 = 0xffffffffL & TlsBuffer.readLittleEndianInt32(currentBlock, 4);
            final long t2 = 0xffffffffL & TlsBuffer.readLittleEndianInt32(currentBlock, 8);
            final long t3 = 0xffffffffL & TlsBuffer.readLittleEndianInt32(currentBlock, 12);

            h0 += t0 & 0x3ffffff;
            h1 += (((t1 << 32) | t0) >>> 26) & 0x3ffffff;
            h2 += (((t2 << 32) | t1) >>> 20) & 0x3ffffff;
            h3 += (((t3 << 32) | t2) >>> 14) & 0x3ffffff;
            h4 += (t3 >>> 8);

            if (currentBlockOffset == BLOCK_SIZE) {
                h4 += (1 << 24);
            }

            long tp0 = mul32x32_64(h0, r0) + mul32x32_64(h1, s4) + mul32x32_64(h2, s3) + mul32x32_64(h3, s2) + mul32x32_64(h4, s1);
            long tp1 = mul32x32_64(h0, r1) + mul32x32_64(h1, r0) + mul32x32_64(h2, s4) + mul32x32_64(h3, s3) + mul32x32_64(h4, s2);
            long tp2 = mul32x32_64(h0, r2) + mul32x32_64(h1, r1) + mul32x32_64(h2, r0) + mul32x32_64(h3, s4) + mul32x32_64(h4, s3);
            long tp3 = mul32x32_64(h0, r3) + mul32x32_64(h1, r2) + mul32x32_64(h2, r1) + mul32x32_64(h3, r0) + mul32x32_64(h4, s4);
            long tp4 = mul32x32_64(h0, r4) + mul32x32_64(h1, r3) + mul32x32_64(h2, r2) + mul32x32_64(h3, r1) + mul32x32_64(h4, r0);

            h0 = (int) tp0 & 0x3ffffff;
            tp1 += (tp0 >>> 26);
            h1 = (int) tp1 & 0x3ffffff;
            tp2 += (tp1 >>> 26);
            h2 = (int) tp2 & 0x3ffffff;
            tp3 += (tp2 >>> 26);
            h3 = (int) tp3 & 0x3ffffff;
            tp4 += (tp3 >>> 26);
            h4 = (int) tp4 & 0x3ffffff;
            h0 += (int) (tp4 >>> 26) * 5;
            h1 += (h0 >>> 26);
            h0 &= 0x3ffffff;
        }

        public int doFinal(final byte[] out, final int outOff) {
            if (outOff + BLOCK_SIZE > out.length) {
                throw new IllegalArgumentException("Output buffer is too short.");
            }

            if (currentBlockOffset > 0) {
                // Process padded final block
                processBlock();
            }

            h1 += (h0 >>> 26);
            h0 &= 0x3ffffff;
            h2 += (h1 >>> 26);
            h1 &= 0x3ffffff;
            h3 += (h2 >>> 26);
            h2 &= 0x3ffffff;
            h4 += (h3 >>> 26);
            h3 &= 0x3ffffff;
            h0 += (h4 >>> 26) * 5;
            h4 &= 0x3ffffff;
            h1 += (h0 >>> 26);
            h0 &= 0x3ffffff;

            int g0, g1, g2, g3, g4, b;
            g0 = h0 + 5;
            b = g0 >>> 26;
            g0 &= 0x3ffffff;
            g1 = h1 + b;
            b = g1 >>> 26;
            g1 &= 0x3ffffff;
            g2 = h2 + b;
            b = g2 >>> 26;
            g2 &= 0x3ffffff;
            g3 = h3 + b;
            b = g3 >>> 26;
            g3 &= 0x3ffffff;
            g4 = h4 + b - (1 << 26);

            b = (g4 >>> 31) - 1;
            int nb = ~b;
            h0 = (h0 & nb) | (g0 & b);
            h1 = (h1 & nb) | (g1 & b);
            h2 = (h2 & nb) | (g2 & b);
            h3 = (h3 & nb) | (g3 & b);
            h4 = (h4 & nb) | (g4 & b);

            long f0, f1, f2, f3;
            f0 = (((h0) | (h1 << 26)) & 0xffffffffl) + (0xffffffffL & k0);
            f1 = (((h1 >>> 6) | (h2 << 20)) & 0xffffffffl) + (0xffffffffL & k1);
            f2 = (((h2 >>> 12) | (h3 << 14)) & 0xffffffffl) + (0xffffffffL & k2);
            f3 = (((h3 >>> 18) | (h4 << 8)) & 0xffffffffl) + (0xffffffffL & k3);

            TlsBuffer.writeLittleEndianInt32((int) f0, out, outOff);
            f1 += (f0 >>> 32);
            TlsBuffer.writeLittleEndianInt32((int) f1, out, outOff + 4);
            f2 += (f1 >>> 32);
            TlsBuffer.writeLittleEndianInt32((int) f2, out, outOff + 8);
            f3 += (f2 >>> 32);
            TlsBuffer.writeLittleEndianInt32((int) f3, out, outOff + 12);

            reset();
            return BLOCK_SIZE;
        }

        public void reset() {
            currentBlockOffset = 0;

            h0 = h1 = h2 = h3 = h4 = 0;
        }

        private static final long mul32x32_64(int i1, int i2) {
            return (i1 & 0xFFFFFFFFL) * i2;
        }
    }

    private static final class State {
        static final int ENC_INIT = 1;
        static final int ENC_AAD = 2;
        static final int ENC_DATA = 3;
        static final int ENC_FINAL = 4;
        static final int DEC_INIT = 5;
        static final int DEC_AAD = 6;
        static final int DEC_DATA = 7;
        static final int DEC_FINAL = 8;
    }
}
