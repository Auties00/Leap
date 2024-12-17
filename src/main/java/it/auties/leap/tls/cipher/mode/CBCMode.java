package it.auties.leap.tls.cipher.mode;

import it.auties.leap.tls.cipher.engine.TlsCipherEngine;

import java.nio.ByteBuffer;

final class CBCMode extends TlsCipherMode.Block {
    private final TlsCipherEngine.Block cipher;
    private ByteBuffer cbcV;
    private ByteBuffer cbcNextV;

    CBCMode(TlsCipherEngine.Block cipher, byte[] iv) {
        super(cipher, iv);
        this.cipher = cipher;
        this.cbcV = ByteBuffer.allocate(cipher.blockSize());
        this.cbcNextV = ByteBuffer.allocate(cipher.blockSize());
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

        if (cipher.forEncryption()) {
            encryptBlock(input, output);
        }else {
            decryptBlock(input, output);
        }
    }

    private void encryptBlock(ByteBuffer input, ByteBuffer output) {
        for (int i = 0; i < cipher.blockSize(); i++) {
            cbcV.put(i, (byte) (cbcV.get(i) ^ input.get()));
        }

        cipher.process(cbcV, output);
    }

    private void decryptBlock(ByteBuffer input, ByteBuffer output) {
        cbcNextV.clear();
        for(var i = 0; i < cipher.blockSize(); i++) {
            cbcNextV.put(input.get());
        }

        var outputPosition = output.position();
        cipher.process(input, output);
        for (int i = 0; i < cipher.blockSize(); i++) {
            var position = outputPosition + i;
            output.put(position, (byte) (output.get(position) ^ cbcV.get(i)));
        }

        var tmp = cbcV;
        cbcV = cbcNextV;
        cbcNextV = tmp;
    }

    @Override
    public void reset() {
        cbcV.put(0, iv);
        cbcNextV.clear();
        cipher.reset();
    }
}
