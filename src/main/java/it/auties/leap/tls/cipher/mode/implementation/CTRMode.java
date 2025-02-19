package it.auties.leap.tls.cipher.mode.implementation;

import it.auties.leap.tls.cipher.engine.TlsCipherEngine;
import it.auties.leap.tls.cipher.engine.implementation.MagmaEngine;
import it.auties.leap.tls.cipher.mode.TlsCipherIV;
import it.auties.leap.tls.cipher.mode.TlsCipherMode;
import it.auties.leap.tls.cipher.mode.TlsCipherModeFactory;
import it.auties.leap.tls.exception.TlsException;
import it.auties.leap.tls.mac.TlsExchangeMac;

import java.nio.ByteBuffer;

public final class CTRMode extends TlsCipherMode.Block {
    private static final TlsCipherModeFactory FACTORY = CNTImitMode::new;

    public CTRMode(TlsCipherEngine engine) {
        super(engine);
    }

    public static TlsCipherModeFactory factory() {
        return FACTORY;
    }

    @Override
    public void init(boolean forEncryption, byte[] key, byte[] fixedIv, TlsExchangeMac authenticator) {
        if(!(engine instanceof MagmaEngine)) {
            throw new TlsException("CTR mode is supported only by Magma engines");
        }
        super.init(forEncryption, key, fixedIv, authenticator);
    }

    @Override
    public void cipher(byte contentType, ByteBuffer input, ByteBuffer output, byte[] sequence) {

    }

    @Override
    public TlsCipherIV ivLength() {
        return new TlsCipherIV(4, 4);
    }

    @Override
    public int tagLength() {
        return 0;
    }

   /*
    private final TlsCipherEngine.Block cipher;
    private final ByteBuffer counter;
    private final ByteBuffer counterOut;

    CTRMode(TlsCipherEngine.Block cipher, byte[] iv) {
        super(cipher, iv);
        this.cipher = cipher;
        this.counter = ByteBuffer.allocate(cipher.blockLength());
        this.counterOut = ByteBuffer.allocate(cipher.blockLength());
        reset();
    }

    @Override
    public int blockLength() {
        return cipher.blockLength();
    }

    @Override
    public void update(ByteBuffer input, ByteBuffer output, boolean last) {
        if (last) {
            return;
        }

        if (counterOut.hasRemaining()) {
            while (input.hasRemaining()) {
                byte next;

                if (!counterOut.hasRemaining()) {
                    cipher.process(counter, counterOut);
                    next = (byte) (input.get() ^ counterOut.get());
                } else {
                    next = (byte) (input.get() ^ counterOut.get());
                    if (!counterOut.hasRemaining()) {
                        counterOut.clear();
                        incrementCounter();
                    }
                }
                output.put(next);
            }
        } else {
            counter.clear();
            counterOut.clear();
            cipher.process(counter, counterOut);

            while (counterOut.hasRemaining()) {
                output.put((byte) (input.get() ^ counterOut.get()));
            }

            incrementCounter();
        }
    }

    private void incrementCounter() {
        int i = counter.capacity();
        while (--i >= 0) {
            var value = counter.get(i);
            counter.put(i, (byte) (value + 1));
            if (value + 1 != 0) {
                break;
            }
        }
    }

    @Override
    public void reset() {
        counter.clear();
        counter.put(fixedIv);
        counterOut.clear();
        cipher.reset();
    }
    */
}