package it.auties.leap.tls.cipher.engine;

import java.nio.ByteBuffer;

public sealed abstract class TlsCipherEngine {
    protected final boolean forEncryption;

    protected TlsCipherEngine(boolean forEncryption) {
        this.forEncryption = forEncryption;
    }

    public abstract void cipher(ByteBuffer input, ByteBuffer output);

    public boolean forEncryption() {
        return forEncryption;
    }

    public non-sealed abstract static class Block extends TlsCipherEngine {
        protected Block(boolean forEncryption) {
            super(forEncryption);
        }

        public abstract int blockLength();
    }

    public non-sealed abstract static class Stream extends TlsCipherEngine {
        protected Stream(boolean forEncryption) {
            super(forEncryption);
        }
    }
}
