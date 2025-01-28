package it.auties.leap.tls.cipher.engine;

import it.auties.leap.tls.cipher.engine.implementation.*;

import java.nio.ByteBuffer;

public sealed abstract class TlsCipherEngine {
    public static TlsCipherEngine aes(boolean forEncryption, byte[] key) {
        return new AESEngine(forEncryption, key);
    }

    public static TlsCipherEngine aria(boolean forEncryption, byte[] key) {
        return new ARIAEngine(forEncryption, key);
    }
    
    public static TlsCipherEngine camellia(boolean forEncryption, byte[] key) {
        return new CamelliaEngine(forEncryption, key);
    }

    public static TlsCipherEngine des(boolean forEncryption, byte[] key) {
        return new DESEngine(forEncryption, key);
    }
    
    public static TlsCipherEngine desEde(boolean forEncryption, byte[] key) {
        return new DESEdeEngine(forEncryption, key);
    }

    public static TlsCipherEngine idea(boolean forEncryption, byte[] key) {
        return new IDEAEngine(forEncryption, key);
    }

    public static TlsCipherEngine kuznyechik(boolean forEncryption, byte[] key) {
        return new KuznyechikEngine(forEncryption, key);
    }

    public static TlsCipherEngine magma(boolean forEncryption, byte[] key) {
        return new MagmaEngine(forEncryption, key);
    }

    public static TlsCipherEngine rc2(boolean forEncryption, byte[] key) {
        return new RC2Engine(forEncryption, key);
    }

    public static TlsCipherEngine rc4(boolean forEncryption, byte[] key) {
        return new RC4Engine(forEncryption, key);
    }

    public static TlsCipherEngine seed(boolean forEncryption, byte[] key) {
        return new SEEDEngine(forEncryption, key);
    }

    public static TlsCipherEngine sm4(boolean forEncryption, byte[] key) {
        return new SM4Engine(forEncryption, key);
    }

    public static TlsCipherEngine none() {
        return NoneEngine.instance();
    }

    public static TlsCipherEngine chaCha20(boolean forEncryption, byte[] key) {
        throw new UnsupportedOperationException();
    }

    protected final byte[] key;
    protected boolean forEncryption;

    private TlsCipherEngine(boolean forEncryption, byte[] key) {
        this.forEncryption = forEncryption;
        this.key = key;
    }

    public abstract void update(ByteBuffer input, ByteBuffer output);

    public abstract void reset();

    public byte[] key() {
        return key;
    }

    public int keyLength() {
        return key.length;
    }

    public boolean forEncryption() {
        return forEncryption;
    }

    public static abstract non-sealed class Block extends TlsCipherEngine {
        protected Block(boolean forEncryption, byte[] key) {
            super(forEncryption, key);
        }

        @Override
        public void reset() {

        }

        public abstract int blockLength();
    }

    public static abstract non-sealed class Stream extends TlsCipherEngine {
        protected Stream(boolean forEncryption, byte[] key) {
            super(forEncryption, key);
        }
    }

}
