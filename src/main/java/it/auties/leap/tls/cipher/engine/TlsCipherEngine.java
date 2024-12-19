package it.auties.leap.tls.cipher.engine;

import java.nio.ByteBuffer;

public sealed abstract class TlsCipherEngine {
    public static TlsCipherEngine aes128() {
        return new AESEngine(16);
    }

    public static TlsCipherEngine aes256() {
        return new AESEngine(32);
    }

    public static TlsCipherEngine aria128() {
        return new ARIAEngine(16);
    }

    public static TlsCipherEngine aria256() {
        return new ARIAEngine(32);
    }

    public static TlsCipherEngine camellia128() {
        return new CamelliaEngine(16);
    }

    public static TlsCipherEngine camellia256() {
        return new CamelliaEngine(32);
    }

    public static TlsCipherEngine des() {
        return new DESEngine(7);
    }

    public static TlsCipherEngine des40() {
        return new DESEngine(5);
    }

    public static TlsCipherEngine desEde() {
        return new DESEdeEngine(21);
    }

    public static TlsCipherEngine idea() {
        return new IDEAEngine();
    }

    public static TlsCipherEngine kuznyechik() {
        return new KuznyechikEngine();
    }

    public static TlsCipherEngine magma() {
        return new MagmaEngine();
    }

    public static TlsCipherEngine rc2() {
        return new RC2Engine();
    }

    public static TlsCipherEngine rc4() {
        return new RC4Engine();
    }

    public static TlsCipherEngine seed() {
        return new SEEDEngine();
    }

    public static TlsCipherEngine sm4() {
        return new SM4Engine();
    }

    public static TlsCipherEngine none() {
        return new NoneEngine();
    }
    
    protected final int keyLength;
    protected boolean forEncryption;
    private TlsCipherEngine(int keyLength) {
        this.keyLength = keyLength;
    }

    public abstract void init(boolean forEncryption, byte[] key);

    public abstract void process(ByteBuffer input, ByteBuffer output);

    public abstract void reset();

    public boolean forEncryption() {
        return forEncryption;
    }

    public static abstract non-sealed class Stream extends TlsCipherEngine {
        protected Stream(int keyLength) {
            super(keyLength);
        }
    }

    public static abstract non-sealed class Block extends TlsCipherEngine {
        protected Block(int keyLength) {
            super(keyLength);
        }

        public abstract int blockLength();
    }
}
