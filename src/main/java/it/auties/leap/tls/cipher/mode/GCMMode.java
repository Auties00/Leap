package it.auties.leap.tls.cipher.mode;

import it.auties.leap.tls.message.TlsMessage;

import java.nio.ByteBuffer;

final class GCMMode extends TlsCipherMode.Block implements TlsCipherMode.AEAD {
    @Override
    public void update(TlsMessage.ContentType contentType, ByteBuffer input, ByteBuffer output, byte[] sequence) {

    }

    @Override
    public void doFinal(TlsMessage.ContentType contentType, ByteBuffer input, ByteBuffer output) {

    }

    @Override
    public void reset() {

    }

    @Override
    public int nonceLength() {
        return 0;
    }
    /*
      GCMWrapper(TlsVersion version, TlsCipher cipher, TlsExchangeAuthenticator authenticator, TlsSessionKeys sessionKeys, TlsMode mode) {
        super(version, cipher, authenticator, sessionKeys, mode);
    }

    @Override
    public void encrypt(ContentType contentType, ByteBuffer input, ByteBuffer output) {
        switch (version) {
            case TLS10, DTLS10, TLS11 -> throw new TlsException("AesGcm ciphers are not allowed before (D)TLSv1.2");
            case TLS12, DTLS12 -> tls12Encrypt(contentType, input, output);
            case TLS13, DTLS13 -> throw new UnsupportedOperationException();
        }
    }

    private void tls12Encrypt(ContentType contentType, ByteBuffer input, ByteBuffer output) {
        var outputPosition = output.position();

        var nonce = authenticator.sequenceNumber();

        var fixedIv = switch (mode) {
            case CLIENT -> sessionKeys.localIv();
            case SERVER -> sessionKeys.remoteIv();
        };
        var iv = Arrays.copyOf(fixedIv, fixedIv.length + nonce.length);
        System.arraycopy(nonce, 0, iv, fixedIv.length, nonce.length);
        var ivSpec = new GCMParameterSpec(128, iv);

        var aad = authenticator.createAuthenticationBlock(
                contentType.id(),
                input.remaining(),
                null
        );

        var outputPositionWithNonce = outputPosition - nonce.length;
        output.position(outputPositionWithNonce);
        output.put(nonce);

        var family = TlsCipherEngine.of(cipher, WRITE, ivSpec, sessionKeys, aad);
        family.wrap(input, output, true);

        output.limit(output.position());
        output.position(outputPositionWithNonce);
    }


    @Override
    public void decrypt(ContentType contentType, ByteBuffer input, ByteBuffer output, byte[] sequence) {
        switch (version) {
            case TLS10, DTLS10, TLS11 -> throw new TlsException("AEAD ciphers are not allowed in (D)TLSv1.3");
            case TLS12, DTLS12 -> tls12Decrypt(contentType, input, output);
            case TLS13, DTLS13 -> throw new UnsupportedOperationException();
        }
    }

    private void tls12Decrypt(ContentType contentType, ByteBuffer input, ByteBuffer output) {
        var outputPosition = output.position();

        var fixedIv = switch (mode) {
            case CLIENT -> sessionKeys.remoteIv();
            case SERVER -> sessionKeys.localIv();
        };

        var recordIvSize = cipher.type().ivLength() - cipher.type().fixedIvLength();
        var iv = Arrays.copyOf(fixedIv, fixedIv.length + recordIvSize);
        input.get(iv, fixedIv.length, recordIvSize);
        var ivSpec = new GCMParameterSpec(128, iv);
        var aad = authenticator.createAuthenticationBlock(
                contentType.id(),
                input.remaining() - cipher.type().tagLength(),
                null
        );

        var family = TlsCipherEngine.of(cipher, READ, ivSpec, sessionKeys, aad);
        family.unwrap(input, output, true);

        output.limit(output.position());
        output.position(outputPosition);
    }

    @Override
    public int nonceLength() {
        return cipher.type().ivLength() - cipher.type().fixedIvLength();
    }
     */
  /*
    private static final int BLOCK_SIZE = 16;

    // not final due to a compiler bug
    private final TlsCipherEngine.Block cipher;
    private final GCMMultiplier multiplier;
    private GCMExponentiator exp;

    // These fields are set by init and not modified by processing
    private final boolean forEncryption;
    private boolean initialised;
    private final int macSize;
    private final byte[] initialAssociatedText;
    private final ByteBuffer H;
    private final byte[] J0;

    // These fields are modified during processing
    private byte[] bufBlock;
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

    GCMMode(TlsCipherEngine.Block c, GCMMultiplier m, byte[] iv, byte[] aad) {
        super(c, iv);
        if (c.blockLength() != BLOCK_SIZE) {
            throw new IllegalArgumentException("cipher required with a block size of " + BLOCK_SIZE + ".");
        }

        if (m == null) {
            m = new GCMMultiplier.Tables4kGCMMultiplier();
        }

        this.cipher = c;
        this.multiplier = m;

        this.forEncryption = c.forEncryption();
        this.macBlock = null;
        this.initialised = true;

        initialAssociatedText = aad;

        macSize = 12;

        this.H = ByteBuffer.allocate(BLOCK_SIZE);
        cipher.process(H, H);

        // GCMMultiplier tables don't change unless the key changes (and are expensive to init)
        multiplier.init(H);
        exp = null;

        this.J0 = new byte[BLOCK_SIZE];

        if (iv.length == 12) {
            System.arraycopy(iv, 0, J0, 0, iv.length);
            this.J0[BLOCK_SIZE - 1] = 0x01;
        } else {
            gHASH(J0, iv, iv.length);
            byte[] X = new byte[BLOCK_SIZE];
            BufferHelper.writeBigEndianInt64((long) iv.length * 8, X, 8);
            gHASHBlock(J0, X);
        }

        this.S = new byte[BLOCK_SIZE];
        this.S_at = new byte[BLOCK_SIZE];
        this.S_atPre = new byte[BLOCK_SIZE];
        this.atBlock = new byte[BLOCK_SIZE];
        this.atBlockPos = 0;
        this.atLength = 0;
        this.atLengthPre = 0;
        this.counter = J0.clone();
        this.blocksRemaining = -2;      // page 8, len(P) <= 2^39 - 256, 1 block used by tag but done on J0
        this.bufOff = 0;
        this.totalLength = 0;

        if (initialAssociatedText != null) {
            updateAAD(initialAssociatedText, 0, initialAssociatedText.length);
        }
    }

    @Override
    public int blockLength() {
        return cipher.blockLength();
    }

    public byte[] getMac() {
        if (macBlock == null) {
            return new byte[macSize];
        }
        return macBlock.clone();
    }

    public int getOutputSize(int len) {
        int totalData = len + bufOff;

        if (forEncryption) {
            return totalData + macSize;
        }

        return totalData < macSize ? 0 : totalData - macSize;
    }

    public int getUpdateOutputSize(int len) {
        int totalData = len + bufOff;
        if (!forEncryption) {
            if (totalData < macSize) {
                return 0;
            }
            totalData -= macSize;
        }
        return totalData - totalData % BLOCK_SIZE;
    }

    public void updateAAD(byte[] in, int inOff, int len) {
        checkStatus();

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

    private void initCipher() {
        if (atLength > 0) {
            System.arraycopy(S_at, 0, S_atPre, 0, BLOCK_SIZE);
            atLengthPre = atLength;
        }

        // Finish hash for partial AAD block
        if (atBlockPos > 0) {
            gHASHPartial(S_atPre, atBlock, 0, atBlockPos);
            atLengthPre += atBlockPos;
        }

        if (atLengthPre > 0) {
            System.arraycopy(S_atPre, 0, S, 0, BLOCK_SIZE);
        }
    }

    public int processByte(byte in, byte[] out, int outOff) {
        checkStatus();

        bufBlock[bufOff] = in;
        if (++bufOff == bufBlock.length) {
            if (forEncryption) {
                encryptBlock(bufBlock, 0, out, outOff);
                bufOff = 0;
            } else {
                decryptBlock(bufBlock, 0, out, outOff);
                System.arraycopy(bufBlock, BLOCK_SIZE, bufBlock, 0, macSize);
                bufOff = macSize;
            }
            return BLOCK_SIZE;
        }
        return 0;
    }

    @Override
    public void update(ByteBuffer input, ByteBuffer output, boolean last) {
        if(last) {
            checkStatus();

            if (totalLength == 0) {
                initCipher();
            }

            int extra = bufOff;

            if (forEncryption) {
                if ((out.length - outOff) < (extra + macSize)) {
                    throw new IllegalArgumentException("Output buffer too short");
                }
            } else {
                if (extra < macSize) {
                    throw new IllegalArgumentException("data too short");
                }
                extra -= macSize;

                if ((out.length - outOff) < extra) {
                    throw new IllegalArgumentException("Output buffer too short");
                }
            }

            if (extra > 0) {
                processPartial(bufBlock, 0, extra, out, outOff);
            }

            atLength += atBlockPos;

            if (atLength > atLengthPre) {

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
        exp = new GCMExponentiator.BasicGCMExponentiator();
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
            BufferHelper.writeBigEndianInt64(atLength * 8, X, 0);
            BufferHelper.writeBigEndianInt64(totalLength * 8, X, 8);

gHASHBlock(S, X);

// T = MSBt(GCTRk(J0,S))
byte[] tag = new byte[BLOCK_SIZE];
            cipher.process(J0, 0, tag, 0);
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
                if (!Arrays.equals(this.macBlock, msgMac)) {
        throw new IllegalArgumentException("mac check in GCM failed");
                }
                        }

reset(false);
        }else {
checkStatus();

var len = in.length;
            if ((in.length - inOff) < len) {
        throw new IllegalArgumentException("Input buffer too short");
            }

int resultLen = 0;

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
                    }
                    }

public void reset() {
    reset(true);
}

private void reset(boolean clearMac) {
    cipher.reset();

    // note: we do not reset the nonce.

    S = new byte[BLOCK_SIZE];
    S_at = new byte[BLOCK_SIZE];
    S_atPre = new byte[BLOCK_SIZE];
    atBlock = new byte[BLOCK_SIZE];
    atBlockPos = 0;
    atLength = 0;
    atLengthPre = 0;
    counter = J0.clone();
    blocksRemaining = -2;
    bufOff = 0;
    totalLength = 0;

    if (bufBlock != null) {
        Arrays.fill(bufBlock, (byte) 0);
    }

    if (clearMac) {
        macBlock = null;
    }

    if (forEncryption) {
        initialised = false;
    } else {
        if (initialAssociatedText != null) {
            updateAAD(initialAssociatedText, 0, initialAssociatedText.length);
        }
    }
}

private void decryptBlock(byte[] buf, int bufOff, byte[] out, int outOff) {
    if ((out.length - outOff) < BLOCK_SIZE) {
        throw new IllegalArgumentException("Output buffer too short");
    }
    if (totalLength == 0) {
        initCipher();
    }

    byte[] ctrBlock = new byte[BLOCK_SIZE];
    getNextCTRBlock(ctrBlock);

    gHASHBlock(S, buf, bufOff);
    GCMUtil.xor(ctrBlock, 0, buf, bufOff, out, outOff);

    totalLength += BLOCK_SIZE;
}

private void encryptBlock(byte[] buf, int bufOff, byte[] out, int outOff) {
    if ((out.length - outOff) < BLOCK_SIZE) {
        throw new IllegalArgumentException("Output buffer too short");
    }
    if (totalLength == 0) {
        initCipher();
    }

    byte[] ctrBlock = new byte[BLOCK_SIZE];

    getNextCTRBlock(ctrBlock);
    GCMUtil.xor(ctrBlock, buf, bufOff);
    gHASHBlock(S, ctrBlock);
    System.arraycopy(ctrBlock, 0, out, outOff, BLOCK_SIZE);

    totalLength += BLOCK_SIZE;
}

private void processPartial(byte[] buf, int off, int len, byte[] out, int outOff) {
    byte[] ctrBlock = new byte[BLOCK_SIZE];
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

private void gHASH(byte[] Y, byte[] b, int len) {
    for (int pos = 0; pos < len; pos += BLOCK_SIZE) {
        int num = Math.min(len - pos, BLOCK_SIZE);
        gHASHPartial(Y, b, pos, num);
    }
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

    cipher.process(counter, 0, block, 0);
}

private void checkStatus() {
    if (!initialised) {
        if (forEncryption) {
            throw new IllegalStateException("GCM cipher cannot be reused for encryption");
        }
        throw new IllegalStateException("GCM cipher needs to be initialised");
    }
}

public sealed static interface GCMExponentiator {
    void init(byte[] x);

    void exponentiateX(long pow, byte[] output);

    final class Tables1kGCMExponentiator implements GCMExponentiator {
        // A lookup table of the power-of-two powers of 'x'
        // - lookupPowX2[i] = x^(2^i)
        private List lookupPowX2;

        public void init(byte[] x) {
            long[] y = GCMUtil.asLongs(x);
            if (lookupPowX2 != null && 0L != GCMUtil.areEqual(y, (long[]) lookupPowX2.get(0))) {
                return;
            }

            lookupPowX2 = new ArrayList(8);
            lookupPowX2.add(y);
        }

        public void exponentiateX(long pow, byte[] output) {
            long[] y = GCMUtil.oneAsLongs();
            int bit = 0;
            while (pow > 0) {
                if ((pow & 1L) != 0) {
                    GCMUtil.multiply(y, getPowX2(bit));
                }
                ++bit;
                pow >>>= 1;
            }

            GCMUtil.asBytes(y, output);
        }

        private long[] getPowX2(int bit) {
            int last = lookupPowX2.size() - 1;
            if (last < bit) {
                long[] prev = (long[]) lookupPowX2.get(last);
                do {
                    long[] next = new long[GCMUtil.SIZE_Long];
                    GCMUtil.square(prev, next);
                    lookupPowX2.add(next);
                    prev = next;
                }
                while (++last < bit);
            }

            return (long[]) lookupPowX2.get(bit);
        }
    }

    final class BasicGCMExponentiator implements GCMExponentiator {
        private long[] x;

        public void init(byte[] x) {
            this.x = GCMUtil.asLongs(x);
        }

        public void exponentiateX(long pow, byte[] output) {
            // Initial value is little-endian 1
            long[] y = GCMUtil.oneAsLongs();

            if (pow > 0) {
                long[] powX = new long[GCMUtil.SIZE_Long];
                GCMUtil.copy(x, powX);

                do {
                    if ((pow & 1L) != 0) {
                        GCMUtil.multiply(y, powX);
                    }
                    GCMUtil.square(powX, powX);
                    pow >>>= 1;
                }
                while (pow > 0);
            }

            GCMUtil.asBytes(y, output);
        }
    }
}

public sealed static interface GCMMultiplier {
    void init(byte[] H);

    void multiplyH(byte[] x);

    final class BasicGCMMultiplier implements GCMMultiplier {
        private long[] H;

        public void init(byte[] H) {
            this.H = GCMUtil.asLongs(H);
        }

        public void multiplyH(byte[] x) {
            GCMUtil.multiply(x, H);
        }
    }

    final class Tables4kGCMMultiplier implements GCMMultiplier {
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
            //        long[] z = new long[2];
            //        GCMUtil.copy(T[x[15] & 0xFF], z);
            //        for (int i = 14; i >= 0; --i)
            //        {
            //            GCMUtil.multiplyP8(z);
            //            GCMUtil.xor(z, T[x[i] & 0xFF]);
            //        }
            //        Pack.longToBigEndian(z, x, 0);

            long[] t = T[x[15] & 0xFF];
            long z0 = t[0], z1 = t[1];

            for (int i = 14; i >= 0; --i) {
                t = T[x[i] & 0xFF];

                long c = z1 << 56;
                z1 = t[1] ^ ((z1 >>> 8) | (z0 << 56));
                z0 = t[0] ^ (z0 >>> 8) ^ c ^ (c >>> 1) ^ (c >>> 2) ^ (c >>> 7);
            }

            BufferHelper.writeBigEndianInt64(z0, x, 0);
            BufferHelper.writeBigEndianInt64(z1, x, 8);
        }
    }

    final class Tables8kGCMMultiplier implements GCMMultiplier {
        private byte[] H;
        private long[][][] T;

        public void init(byte[] H) {
            if (T == null) {
                T = new long[2][256][2];
            } else if (0 != GCMUtil.areEqual(this.H, H)) {
                return;
            }

            this.H = new byte[GCMUtil.SIZE_BYTES];
            GCMUtil.copy(H, this.H);

            for (int i = 0; i < 2; ++i) {
                long[][] t = T[i];

                // t[0] = 0

                if (i == 0) {
                    // t[1] = H.p^7
                    GCMUtil.asLongs(this.H, t[1]);
                    GCMUtil.multiplyP7(t[1], t[1]);
                } else {
                    // t[1] = T[i-1][1].p^8
                    GCMUtil.multiplyP8(T[i - 1][1], t[1]);
                }

                for (int n = 2; n < 256; n += 2) {
                    // t[2.n] = t[n].p^-1
                    GCMUtil.divideP(t[n >> 1], t[n]);

                    // t[2.n + 1] = t[2.n] + t[1]
                    GCMUtil.xor(t[n], t[1], t[n + 1]);
                }
            }
        }

        public void multiplyH(byte[] x) {
            long[][] T0 = T[0], T1 = T[1];

            long[] u = T0[x[14] & 0xFF];
            long[] v = T1[x[15] & 0xFF];
            long z0 = u[0] ^ v[0], z1 = u[1] ^ v[1];

            for (int i = 12; i >= 0; i -= 2) {
                u = T0[x[i] & 0xFF];
                v = T1[x[i + 1] & 0xFF];

                long c = z1 << 48;
                z1 = u[1] ^ v[1] ^ ((z1 >>> 16) | (z0 << 48));
                z0 = u[0] ^ v[0] ^ (z0 >>> 16) ^ c ^ (c >>> 1) ^ (c >>> 2) ^ (c >>> 7);
            }

            BufferHelper.writeBigEndianInt64(z0, x, 0);
            BufferHelper.writeBigEndianInt64(z1, x, 8);
        }
    }

    final class Tables64kGCMMultiplier implements GCMMultiplier {
        private byte[] H;
        private long[][][] T;

        public void init(byte[] H) {
            if (T == null) {
                T = new long[16][256][2];
            } else if (0 != GCMUtil.areEqual(this.H, H)) {
                return;
            }

            this.H = new byte[GCMUtil.SIZE_BYTES];
            GCMUtil.copy(H, this.H);

            for (int i = 0; i < 16; ++i) {
                long[][] t = T[i];

                // t[0] = 0

                if (i == 0) {
                    // t[1] = H.p^7
                    GCMUtil.asLongs(this.H, t[1]);
                    GCMUtil.multiplyP7(t[1], t[1]);
                } else {
                    // t[1] = T[i-1][1].p^8
                    GCMUtil.multiplyP8(T[i - 1][1], t[1]);
                }

                for (int n = 2; n < 256; n += 2) {
                    // t[2.n] = t[n].p^-1
                    GCMUtil.divideP(t[n >> 1], t[n]);

                    // t[2.n + 1] = t[2.n] + t[1]
                    GCMUtil.xor(t[n], t[1], t[n + 1]);
                }
            }
        }

        public void multiplyH(byte[] x) {
            long[] t00 = T[0][x[0] & 0xFF];
            long[] t01 = T[1][x[1] & 0xFF];
            long[] t02 = T[2][x[2] & 0xFF];
            long[] t03 = T[3][x[3] & 0xFF];
            long[] t04 = T[4][x[4] & 0xFF];
            long[] t05 = T[5][x[5] & 0xFF];
            long[] t06 = T[6][x[6] & 0xFF];
            long[] t07 = T[7][x[7] & 0xFF];
            long[] t08 = T[8][x[8] & 0xFF];
            long[] t09 = T[9][x[9] & 0xFF];
            long[] t10 = T[10][x[10] & 0xFF];
            long[] t11 = T[11][x[11] & 0xFF];
            long[] t12 = T[12][x[12] & 0xFF];
            long[] t13 = T[13][x[13] & 0xFF];
            long[] t14 = T[14][x[14] & 0xFF];
            long[] t15 = T[15][x[15] & 0xFF];

            long z0 = t00[0] ^ t01[0] ^ t02[0] ^ t03[0] ^ t04[0] ^ t05[0] ^ t06[0] ^ t07[0] ^ t08[0] ^ t09[0] ^ t10[0] ^ t11[0] ^ t12[0] ^ t13[0] ^ t14[0] ^ t15[0];
            long z1 = t00[1] ^ t01[1] ^ t02[1] ^ t03[1] ^ t04[1] ^ t05[1] ^ t06[1] ^ t07[1] ^ t08[1] ^ t09[1] ^ t10[1] ^ t11[1] ^ t12[1] ^ t13[1] ^ t14[1] ^ t15[1];

            BufferHelper.writeBigEndianInt64(z0, x, 0);
            BufferHelper.writeBigEndianInt64(z1, x, 8);
        }
    }
}

public static final class GCMUtil {
    private static final long M64R = 0xAAAAAAAAAAAAAAAAL;
    public static final int SIZE_BYTES = 16;
    public static final int SIZE_Long = 2;

    private static final int E1 = 0xe1000000;
    private static final long E1L = (E1 & 0xFFFFFFFFL) << 32;

    public static long[] oneAsLongs() {
        long[] tmp = new long[SIZE_Long];
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

    public static long areEqual(long[] x, long[] y) {
        long d = 0L;
        d |= x[0] ^ y[0];
        d |= x[1] ^ y[1];
        d = (d >>> 1) | (d & 1L);
        return (d - 1L) >> 63;
    }

    public static void asBytes(long[] x, byte[] z) {
        BufferHelper.writeBigEndianInt64(x, 0, SIZE_Long, z, 0);
    }

    public static long[] asLongs(byte[] x) {
        long[] z = new long[SIZE_Long];
        BufferHelper.bigEndianToLong(x, 0, z, 0, SIZE_Long);
        return z;
    }

    public static void asLongs(byte[] x, long[] z) {
        BufferHelper.bigEndianToLong(x, 0, z, 0, SIZE_Long);
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

    static void multiply(byte[] x, long[] y) {

        long x0 = BufferHelper.bigEndianToLong(x, 0);
        long x1 = BufferHelper.bigEndianToLong(x, 8);
        long y0 = y[0], y1 = y[1];
        long x0r = Long.reverse(x0), x1r = Long.reverse(x1);
        long y0r = Long.reverse(y0), y1r = Long.reverse(y1);

        long h0 = Long.reverse(implMul64(x0r, y0r));
        long h1 = implMul64(x0, y0) << 1;
        long h2 = Long.reverse(implMul64(x1r, y1r));
        long h3 = implMul64(x1, y1) << 1;
        long h4 = Long.reverse(implMul64(x0r ^ x1r, y0r ^ y1r));
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

        BufferHelper.writeBigEndianInt64(z0, x, 0);
        BufferHelper.writeBigEndianInt64(z1, x, 8);
    }

    public static void multiply(long[] x, long[] y) {
        long x0 = x[0], x1 = x[1];
        long y0 = y[0], y1 = y[1];
        long x0r = Long.reverse(x0), x1r = Long.reverse(x1);
        long y0r = Long.reverse(y0), y1r = Long.reverse(y1);

        long h0 = Long.reverse(implMul64(x0r, y0r));
        long h1 = implMul64(x0, y0) << 1;
        long h2 = Long.reverse(implMul64(x1r, y1r));
        long h3 = implMul64(x1, y1) << 1;
        long h4 = Long.reverse(implMul64(x0r ^ x1r, y0r ^ y1r));
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

    public static void multiplyP8(long[] x, long[] y) {
        long x0 = x[0], x1 = x[1];
        long c = x1 << 56;
        y[0] = (x0 >>> 8) ^ c ^ (c >>> 1) ^ (c >>> 2) ^ (c >>> 7);
        y[1] = (x1 >>> 8) | (x0 << 56);
    }

    public static void square(long[] x, long[] z) {
        long[] t = new long[SIZE_Long * 2];
        expand64To128Rev(x[0], t, 0);
        expand64To128Rev(x[1], t, 2);

        long z0 = t[0], z1 = t[1], z2 = t[2], z3 = t[3];

        z1 ^= z3 ^ (z3 >>> 1) ^ (z3 >>> 2) ^ (z3 >>> 7);
        z2 ^= (z3 << 63) ^ (z3 << 62) ^ (z3 << 57);

        z0 ^= z2 ^ (z2 >>> 1) ^ (z2 >>> 2) ^ (z2 >>> 7);
        z1 ^= (z2 << 63) ^ (z2 << 62) ^ (z2 << 57);

        z[0] = z0;
        z[1] = z1;
    }

    public static void expand64To128Rev(long x, long[] z, int zOff) {
        // "shuffle" low half to even bits and high half to odd bits
        x = bitPermuteStep(x, 0x00000000FFFF0000L, 16);
        x = bitPermuteStep(x, 0x0000FF000000FF00L, 8);
        x = bitPermuteStep(x, 0x00F000F000F000F0L, 4);
        x = bitPermuteStep(x, 0x0C0C0C0C0C0C0C0CL, 2);
        x = bitPermuteStep(x, 0x2222222222222222L, 1);

        z[zOff] = (x) & M64R;
        z[zOff + 1] = (x << 1) & M64R;
    }

    public static long bitPermuteStep(long x, long m, int s) {
        long t = (x ^ (x >>> s)) & m;
        return (t ^ (t << s)) ^ x;
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
   */
}
