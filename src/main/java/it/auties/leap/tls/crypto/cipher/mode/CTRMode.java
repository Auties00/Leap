package it.auties.leap.tls.crypto.cipher.mode;

import it.auties.leap.tls.crypto.cipher.engine.TlsCipherEngine;

import java.nio.ByteBuffer;

final class CTRMode implements TlsCipherMode.Block {
    private final TlsCipherEngine.Block cipher;
    private byte[] iv;
    private final ByteBuffer counter;
    private final ByteBuffer counterOut;
    
    CTRMode(TlsCipherEngine.Block cipher, byte[] iv) {
        this.cipher = cipher;
        this.iv = new byte[cipher.blockSize()];
        this.counter = ByteBuffer.allocate(cipher.blockSize());
        this.counterOut = ByteBuffer.allocate(cipher.blockSize());
        this.iv = iv;
        reset();
    }

    @Override
    public int blockSize() {
        return cipher.blockSize();
    }

    @Override
    public void update(ByteBuffer input, ByteBuffer output, boolean last) {
        if(last) {
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
        }else {
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
        counter.put(iv);
        counterOut.clear();
        cipher.reset();
    }
}
