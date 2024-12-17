package it.auties.leap.tls.cipher.engine;

import java.nio.ByteBuffer;

sealed public abstract class TlsCipherEngine {
    protected final boolean forEncryption;
    protected final byte[] key;

    private TlsCipherEngine(boolean forEncryption, byte[] key) {
        this.forEncryption = forEncryption;
        this.key = key;
    }

    public boolean forEncryption() {
        return forEncryption;
    }

    public byte[] key() {
        return key;
    }

    public abstract void process(ByteBuffer input, ByteBuffer output);

    public abstract void reset();

    public static abstract non-sealed class Stream extends TlsCipherEngine {
        protected Stream(boolean forEncryption, byte[] key) {
            super(forEncryption, key);
        }
    }

    public static abstract non-sealed class Block extends TlsCipherEngine {
        protected Block(boolean forEncryption, byte[] key) {
            super(forEncryption, key);
        }

        public abstract int blockSize();
    }
}
