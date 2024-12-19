package it.auties.leap.tls.cipher.engine;

import java.nio.ByteBuffer;

final class NoneEngine extends TlsCipherEngine.Block {
    NoneEngine() {
        super(0);
    }

    @Override
    public void init(boolean forEncryption, byte[] key) {
        this.forEncryption = forEncryption;
    }

    @Override
    public void process(ByteBuffer input, ByteBuffer output) {

    }

    @Override
    public void reset() {

    }

    @Override
    public int blockLength() {
        return 0;
    }
}
