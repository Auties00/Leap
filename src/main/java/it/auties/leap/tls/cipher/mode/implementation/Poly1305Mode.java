package it.auties.leap.tls.cipher.mode.implementation;

import it.auties.leap.tls.cipher.engine.TlsCipherEngine;
import it.auties.leap.tls.cipher.engine.implementation.ChaCha20Engine;
import it.auties.leap.tls.cipher.mode.TlsCipherMode;
import it.auties.leap.tls.cipher.mode.TlsCipherModeFactory;
import it.auties.leap.tls.TlsContext;
import it.auties.leap.tls.exception.TlsException;
import it.auties.leap.tls.mac.TlsExchangeMac;
import it.auties.leap.tls.message.TlsMessage;
import it.auties.leap.tls.message.TlsMessageMetadata;
import it.auties.leap.tls.util.BufferUtils;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

import java.nio.ByteBuffer;

public class Poly1305Mode extends TlsCipherMode.Stream {
    private static final TlsCipherModeFactory FACTORY = Poly1305Mode::new;

    public static TlsCipherModeFactory factory() {
        return FACTORY;
    }

    private static final class State {
        static final int UNINITIALIZED = 0;
        static final int ENC_INIT = 1;
        static final int ENC_AAD = 2;
        static final int ENC_DATA = 3;
        static final int ENC_FINAL = 4;
        static final int DEC_INIT = 5;
        static final int DEC_AAD = 6;
        static final int DEC_DATA = 7;
        static final int DEC_FINAL = 8;
    }

    private static final int BUF_SIZE = 64;
    private static final int MAC_SIZE = 16;
    private static final byte[] ZEROES = new byte[MAC_SIZE - 1];

    private static final long AAD_LIMIT = Long.MAX_VALUE - Long.MIN_VALUE;
    private static final long DATA_LIMIT = ((1L << 32) - 1) * 64;

    private final Mac poly1305;

    private final byte[] buf = new byte[BUF_SIZE + MAC_SIZE];
    private final byte[] mac = new byte[MAC_SIZE];

    private long aadCount;
    private long dataCount;
    private int state = State.UNINITIALIZED;
    private int bufPos;

    private Poly1305Mode(TlsCipherEngine engine) {
        if(!(engine instanceof ChaCha20Engine)) {
            throw new TlsException("POLY1305 mode is supported only by ChaCha20 engines");
        }
        super(engine);
        this.poly1305 = new Mac();
    }

    @Override
    public void init(boolean forEncryption, byte[] key, byte[] fixedIv, TlsExchangeMac authenticator) {
        super.init(forEncryption, key, fixedIv, authenticator);
        engine.init(forEncryption, key);
    }

    @Override
    public void encrypt(TlsContext context, TlsMessage message, ByteBuffer output) {
        var input = output.duplicate();
        message.serializeMessage(input);
        var initialPosition = output.position();
        this.state = engine.forEncryption() ? State.ENC_INIT : State.DEC_INIT;
            byte[] sn = authenticator.sequenceNumber();
            byte[] nonce = new byte[fixedIv.length];
            System.arraycopy(sn, 0, nonce, nonce.length - sn.length, sn.length);
            for (int i = 0; i < nonce.length; i++) {
                nonce[i] ^= fixedIv[i];
            }

            ((ChaCha20Engine) engine).initIV(nonce);
            reset(true);

            byte[] aad = authenticator.createAuthenticationBlock(
                    message.contentType().type(), input.remaining(), null);
            processAADBytes(aad, 0, aad.length);
            System.out.println("IV: " + java.util.Arrays.toString(nonce));
            System.out.println("AAD: " + java.util.Arrays.toString(aad));
            var result  = processBytes(input.array(), input.position(), input.remaining(), output.array(), output.position());
            result += doFinal(output.array(), output.position() + result);
            output.position(output.position() + result);
        output.limit(output.position());
        output.position(initialPosition);
    }

    @Override
    public ByteBuffer decrypt(TlsContext context, TlsMessageMetadata metadata, ByteBuffer input) {
        var output = input.duplicate();
        var initialPosition = output.position();
        this.state = engine.forEncryption() ? State.ENC_INIT : State.DEC_INIT;

        byte[] sn = null;
        if (sn == null) {
            sn = authenticator.sequenceNumber();
        }
        byte[] nonce = new byte[fixedIv.length];
        System.arraycopy(sn, 0, nonce, nonce.length - sn.length, sn.length);
        for (int i = 0; i < nonce.length; i++) {
            nonce[i] ^= fixedIv[i];
        }

        ((ChaCha20Engine) engine).initIV(nonce);
        reset(true);

        // update the additional authentication data
        byte[] aad = authenticator.createAuthenticationBlock(metadata.contentType().type(), input.remaining() - tagLength(), null);
        processAADBytes(aad, 0, aad.length);

        var result  = processBytes(input.array(), input.position(), input.remaining(), output.array(), output.position());
        result += doFinal(output.array(), output.position() + result);
        output.position(output.position() + result);
        output.limit(output.position());
        output.position(initialPosition);

        return output;
    }

    @Override
    public int ivLength() {
        return 12;
    }

    @Override
    public int fixedIvLength() {
        return 0;
    }

    @Override
    public int tagLength() {
        return 16;
    }

    public void processAADBytes(byte[] in, int inOff, int len) {
        checkAAD();
        if (len > 0) {
            this.aadCount = incrementCount(aadCount, len, AAD_LIMIT);
            poly1305.update(in, inOff, len);
        }
    }

    public int processBytes(byte[] in, int inOff, int len, byte[] out, int outOff) throws DataLengthException {
        checkData();

        int resultLen = 0;

        switch (state) {
            case State.DEC_DATA: {
                for (int i = 0; i < len; ++i) {
                    buf[bufPos] = in[inOff + i];
                    if (++bufPos == buf.length) {
                        poly1305.update(buf, 0, BUF_SIZE);
                        processData(buf, 0, BUF_SIZE, out, outOff + resultLen);
                        System.arraycopy(buf, BUF_SIZE, buf, 0, MAC_SIZE);
                        this.bufPos = MAC_SIZE;
                        resultLen += BUF_SIZE;
                    }
                }
                break;
            }
            case State.ENC_DATA: {
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
                break;
            }
            default:
                throw new IllegalStateException();
        }

        return resultLen;
    }

    public int doFinal(byte[] out, int outOff){
        if (null == out) {
            throw new NullPointerException("'out' cannot be null");
        }
        if (outOff < 0) {
            throw new IllegalArgumentException("'outOff' cannot be negative");
        }

        checkData();

        Arrays.clear(mac);

        int resultLen = 0;

        switch (state) {
            case State.DEC_DATA: {
                if (bufPos < MAC_SIZE) {
                    throw new RuntimeException("data too short");
                }

                resultLen = bufPos - MAC_SIZE;

                if (outOff > (out.length - resultLen)) {
                    throw new OutputLengthException("Output buffer too short");
                }

                if (resultLen > 0) {
                    poly1305.update(buf, 0, resultLen);
                    processData(buf, 0, resultLen, out, outOff);
                }

                finishData(State.DEC_FINAL);

                if (!Arrays.constantTimeAreEqual(MAC_SIZE, mac, 0, buf, resultLen)) {
                    throw new RuntimeException("mac check in ChaCha20Poly1305 failed");
                }

                break;
            }
            case State.ENC_DATA: {
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
                break;
            }
            default:
                throw new IllegalStateException();
        }

        reset(false);

        return resultLen;
    }

    private void checkAAD() {
        switch (state) {
            case State.DEC_INIT:
                this.state = State.DEC_AAD;
                break;
            case State.ENC_INIT:
                this.state = State.ENC_AAD;
                break;
            case State.DEC_AAD:
            case State.ENC_AAD:
                break;
            case State.ENC_FINAL:
                throw new IllegalStateException("ChaCha20Poly1305 cannot be reused for encryption");
            default:
                throw new IllegalStateException();
        }
    }

    private void checkData() {
        switch (state) {
            case State.DEC_INIT:
            case State.DEC_AAD:
                finishAAD(State.DEC_DATA);
                break;
            case State.ENC_INIT:
            case State.ENC_AAD:
                finishAAD(State.ENC_DATA);
                break;
            case State.DEC_DATA:
            case State.ENC_DATA:
                break;
            case State.ENC_FINAL:
                throw new IllegalStateException("ChaCha20Poly1305 cannot be reused for encryption");
            default:
                throw new IllegalStateException();
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
            engine.cipher(ByteBuffer.wrap(firstBlock, 0, 64), ByteBuffer.wrap(firstBlock, 0, firstBlock.length));
            poly1305.init(Arrays.copyOf(firstBlock, 32));
        } finally {
            Arrays.clear(firstBlock);
        }
    }

    private void padMAC(long count) {
        int partial = (int) count & (MAC_SIZE - 1);
        if (0 != partial) {
            poly1305.update(ZEROES, 0, MAC_SIZE - partial);
        }
    }

    private void processData(byte[] in, int inOff, int inLen, byte[] out, int outOff) {
        if (outOff > (out.length - inLen)) {
            throw new OutputLengthException("Output buffer too short");
        }

        engine.cipher(ByteBuffer.wrap(in, inOff, inLen), ByteBuffer.wrap(out, outOff, out.length - outOff));

        this.dataCount = incrementCount(dataCount, inLen, DATA_LIMIT);
    }

    private void reset(boolean clearMac) {
        Arrays.clear(buf);

        if (clearMac) {
            Arrays.clear(mac);
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

        initMAC();
    }

    private static final class Mac {
        private static final int BLOCK_SIZE = 16;

        private final byte[] currentBlock;
        private int r0, r1, r2, r3, r4;
        private int s1, s2, s3, s4;
        private int k0, k1, k2, k3;
        private int currentBlockOffset = 0;
        private int h0, h1, h2, h3, h4;

        private Mac() {
            this.currentBlock = new byte[BLOCK_SIZE];
        }

        public void init(byte[] key) {
            if (key.length != 32) {
                throw new IllegalArgumentException("Poly1305 key must be 256 bits.");
            }

            // Extract r portion of key (and "clamp" the values)
            int t0 = Pack.littleEndianToInt(key, 0);
            int t1 = Pack.littleEndianToInt(key, 4);
            int t2 = Pack.littleEndianToInt(key, 8);
            int t3 = Pack.littleEndianToInt(key, 12);

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

            k0 = Pack.littleEndianToInt(kBytes, kOff);
            k1 = Pack.littleEndianToInt(kBytes, kOff + 4);
            k2 = Pack.littleEndianToInt(kBytes, kOff + 8);
            k3 = Pack.littleEndianToInt(kBytes, kOff + 12);

            reset();
        }

        public void update(byte[] in, int inOff, int len) {
            int copied = 0;
            while (len > copied)
            {
                if (currentBlockOffset == BLOCK_SIZE)
                {
                    processBlock();
                    currentBlockOffset = 0;
                }

                int toCopy = Math.min((len - copied), BLOCK_SIZE - currentBlockOffset);
                System.arraycopy(in, copied + inOff, currentBlock, currentBlockOffset, toCopy);
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

            final long t0 = 0xffffffffL & Pack.littleEndianToInt(currentBlock, 0);
            final long t1 = 0xffffffffL & Pack.littleEndianToInt(currentBlock, 4);
            final long t2 = 0xffffffffL & Pack.littleEndianToInt(currentBlock, 8);
            final long t3 = 0xffffffffL & Pack.littleEndianToInt(currentBlock, 12);

            h0 += (int) (t0 & 0x3ffffff);
            h1 += (int) ((((t1 << 32) | t0) >>> 26) & 0x3ffffff);
            h2 += (int) ((((t2 << 32) | t1) >>> 20) & 0x3ffffff);
            h3 += (int) ((((t3 << 32) | t2) >>> 14) & 0x3ffffff);
            h4 += (int) (t3 >>> 8);

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

        public int doFinal(byte[] output, int offset) {
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
            f0 = (((h0) | ((long) h1 << 26)) & 0xffffffffL) + (0xffffffffL & k0);
            f1 = (((h1 >>> 6) | ((long) h2 << 20)) & 0xffffffffL) + (0xffffffffL & k1);
            f2 = (((h2 >>> 12) | ((long) h3 << 14)) & 0xffffffffL) + (0xffffffffL & k2);
            f3 = (((h3 >>> 18) | ((long) h4 << 8)) & 0xffffffffL) + (0xffffffffL & k3);

            BufferUtils.writeLittleEndianInt32((int) f0, output, offset);
            f1 += (f0 >>> 32);
            BufferUtils.writeLittleEndianInt32((int) f1, output, offset + 4);
            f2 += (f1 >>> 32);
            BufferUtils.writeLittleEndianInt32((int) f2, output, offset + 8);
            f3 += (f2 >>> 32);
            BufferUtils.writeLittleEndianInt32((int) f3, output, offset + 12);

            reset();
            return BLOCK_SIZE;
        }

        public void reset() {
            currentBlockOffset = 0;

            h0 = h1 = h2 = h3 = h4 = 0;
        }

        private static long mul32x32_64(int i1, int i2) {
            return (i1 & 0xFFFFFFFFL) * i2;
        }
    }
}
