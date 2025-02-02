package it.auties.leap.tls.cipher.mode.implementation;

import it.auties.leap.tls.cipher.TlsCipherIV;
import it.auties.leap.tls.cipher.engine.TlsCipherEngine;
import it.auties.leap.tls.cipher.mode.TlsCipherMode;
import it.auties.leap.tls.cipher.mode.TlsCipherModeFactory;
import it.auties.leap.tls.cipher.auth.TlsExchangeAuthenticator;

import java.nio.ByteBuffer;

public final class CCMMode extends TlsCipherMode.Block {
    private static final TlsCipherModeFactory FACTORY = CCMMode::new;

    public static TlsCipherModeFactory factory() {
        return FACTORY;
    }

    @Override
    public void init(TlsExchangeAuthenticator authenticator, TlsCipherEngine engine, byte[] fixedIv) {
        super.init(authenticator, engine, fixedIv);
    }

    @Override
    public void update(byte contentType, ByteBuffer input, ByteBuffer output, byte[] sequence) {

    }

    @Override
    public void doFinal(byte contentType, ByteBuffer input, ByteBuffer output) {

    }

    @Override
    public void reset() {

    }

    @Override
    public TlsCipherIV ivLength() {
        return new TlsCipherIV(4, 8);
    }

    @Override
    public int tagLength() {
        return 0;
    }

   /*
    private static final int MAC_SIZE = 8;

    private final TlsCipherEngine.Block cipher;
    private final ByteBuffer macBlock;
    private byte[] aad;
    private final ByteArrayOutputStream data;

    CCMMode(TlsCipherEngine.Block cipher, byte[] iv) {
        super(cipher, iv);
        this.cipher = cipher;
        this.macBlock = ByteBuffer.allocate(cipher.blockLength());
        this.data = new ByteArrayOutputStream();
        reset();
    }

    @Override
    public int blockLength() {
        return cipher.blockLength();
    }

    @Override
    public void update(ByteBuffer input, ByteBuffer output, boolean last) {
        if (!last) {
            update(input);
        } else {
            doFinal(input, output);
        }
    }

    private void update(ByteBuffer input) {
        while (input.hasRemaining()) {
            data.write(input.get());
        }
    }

    private void doFinal(ByteBuffer input, ByteBuffer output) {
        var q = 15 - fixedIv.length;
        var iv = new byte[cipher.blockLength()];
        iv[0] = (byte) ((q - 1) & 0x7);
        System.arraycopy(this.fixedIv, 0, iv, 1, this.fixedIv.length);
        var ctrCipher = new CTRMode(cipher, iv);
        if (cipher.forEncryption()) {
            encryptBlock(input, output, ctrCipher);
        } else {
            decryptBlock(input, output, ctrCipher);
        }
        reset();
    }

    private void encryptBlock(ByteBuffer input, ByteBuffer output, CTRMode ctrCipher) {
        calculateMac(input, macBlock);

        var encMac = ByteBuffer.allocate(cipher.blockLength());

        ctrCipher.update(macBlock, encMac, false);

        while (input.remaining() >= cipher.blockLength()) {
            ctrCipher.update(input, output, false);
        }

        var block = ByteBuffer.allocate(cipher.blockLength());
        block.put(input);
        block.position(0);

        ctrCipher.update(block, block, false);

        output.put(block);
        output.put(encMac);
    }

    private void decryptBlock(ByteBuffer input, ByteBuffer output, CTRMode ctrCipher) {
        macBlock.put(input);

        ctrCipher.update(macBlock, macBlock, false);

        for (int i = MAC_SIZE; i < macBlock.limit(); i++) {
            macBlock.put(i, (byte) 0);
        }

        while (input.remaining() >= cipher.blockLength()) {
            ctrCipher.update(input, output, false);
        }

        var block = ByteBuffer.allocate(cipher.blockLength());
        block.put(input);
        ctrCipher.update(block, block, false);

        output.put(block);

        var calculatedMacBlock = ByteBuffer.allocate(cipher.blockLength());

        calculateMac(output, calculatedMacBlock);

        if (macBlock.mismatch(calculatedMacBlock) != -1) {
            throw new IllegalArgumentException("mac check in CCM failed");
        }
    }

    @Override
    public void reset() {
        cipher.reset();
        data.reset();
    }

    private void calculateMac(ByteBuffer data, ByteBuffer macBlock) {
        var cMac = new CBCBlockCipherMac(cipher, fixedIv);

        var b0 = ByteBuffer.allocate(16);

        var first = (byte) ((((cipher.blockLength() / 2 - 2) / 2) & 0x7) << 3);
        var second = (byte) (((15 - fixedIv.length) - 1) & 0x7);
        if (aad != null) {
            b0.put((byte) (0x40 | first | second));
        } else {
            b0.put((byte) (first | second));
        }
        b0.put(fixedIv);

        var q = data.remaining();
        var count = 1;
        while (q > 0) {
            b0.put(b0.capacity() - count, (byte) (q & 0xff));
            q >>>= 8;
            count++;
        }

        cMac.update(b0, false);

        if (aad != null) {
            int extra;

            int textLength = aad.length;
            if (textLength < ((1 << 16) - (1 << 8))) {
                cMac.update((byte) (textLength >> 8));
                cMac.update((byte) textLength);

                extra = 2;
            } else // can't go any higher than 2^32
            {
                cMac.update((byte) 0xff);
                cMac.update((byte) 0xfe);
                cMac.update((byte) (textLength >> 24));
                cMac.update((byte) (textLength >> 16));
                cMac.update((byte) (textLength >> 8));
                cMac.update((byte) textLength);

                extra = 6;
            }

            cMac.update(ByteBuffer.wrap(aad), false);

            extra = (extra + textLength) % 16;
            if (extra != 0) {
                for (int i = extra; i != 16; i++) {
                    cMac.update((byte) 0x00);
                }
            }
        }

        cMac.update(data, false);

        cMac.update(macBlock, true);
    }

    private static final class CBCBlockCipherMac {
        private final ByteBuffer mac;
        private final ByteBuffer buf;
        private final TlsCipherMode.Block cipher;

        private CBCBlockCipherMac(TlsCipherEngine.Block cipher, byte[] iv) {
            this.cipher = TlsCipherMode.cbc().newCipherMode(cipher, iv);
            this.mac = ByteBuffer.allocate(cipher.blockLength());
            this.buf = ByteBuffer.allocate(cipher.blockLength());
        }

        private void update(byte input) {
            process();
            buf.put(input);
        }

        private void update(ByteBuffer input, boolean last) {
            if (last) {
                while (buf.hasRemaining()) {
                    buf.put((byte) 0);
                }
                cipher.update(buf, mac.clear(), true, );
                buf.position(0)
                        .limit(cipher.blockLength() / 2);
            } else {
                while (input.hasRemaining()) {
                    buf.put(input);
                    process();
                }
            }
        }

        private void process() {
            if (buf.hasRemaining()) {
                return;
            }

            cipher.update(buf, mac.clear(), false, );
            buf.clear();
        }
    }
    */
}