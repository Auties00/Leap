package it.auties.leap.tls.cipher.engine;

import it.auties.leap.tls.exception.TlsException;

import java.nio.ByteBuffer;
import java.util.OptionalInt;

public sealed abstract class TlsCipherEngine permits TlsCipherEngine.Block, TlsCipherEngine.Stream {
    protected final int keyLength;
    protected byte[] key;
    protected boolean forEncryption;
    protected boolean initialized;

    protected TlsCipherEngine(int keyLength) {
        this.keyLength = keyLength;
    }
    
    public void init(boolean forEncryption, byte[] key) {
        if(initialized) {
            throw new TlsException("Engine is already initialized");
        }

        if ((keyLength != 0 || key != null) && (key == null || key.length != keyLength)) {
            throw new TlsException("Unexpected key size");
        }

        this.forEncryption = forEncryption;
        this.key = key;
        this.initialized = true;
    }

    public abstract void cipher(ByteBuffer input, ByteBuffer output);

    public byte[] key() {
        return key;
    }

    public int keyLength() {
        return keyLength;
    }
    
    public OptionalInt exportedKeyLength() {
        return OptionalInt.empty();
    }

    public boolean forEncryption() {
        return forEncryption;
    }

    public boolean isInitialized() {
        return initialized;
    }

    public static abstract non-sealed class Block extends TlsCipherEngine {
        protected Block(int keyLength) {
            super(keyLength);
        }

        public abstract int blockLength();
    }

    public static abstract non-sealed class Stream extends TlsCipherEngine {
        protected Stream(int keyLength) {
            super(keyLength);
        }
    }
}
