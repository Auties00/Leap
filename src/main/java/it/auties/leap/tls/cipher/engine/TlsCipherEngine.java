package it.auties.leap.tls.cipher.engine;

import it.auties.leap.tls.cipher.engine.implementation.*;
import it.auties.leap.tls.exception.TlsException;

import java.nio.ByteBuffer;
import java.util.OptionalInt;

public sealed abstract class TlsCipherEngine permits TlsCipherEngine.Block, TlsCipherEngine.Stream {
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

    public static TlsCipherEngine des40() {
        return new DESEngine();
    }
    
    public static TlsCipherEngine desEde() {
        return new DESEdeEngine();
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

    public static TlsCipherEngine rc2_40() {
        return new RC2Engine(5);
    }

    public static TlsCipherEngine rc2_128() {
        return new RC2Engine(16);
    }

    public static TlsCipherEngine rc4_40() {
        return new RC4Engine(5);
    }

    public static TlsCipherEngine rc4_128() {
        return new RC4Engine(16);
    }

    public static TlsCipherEngine seed() {
        return new SEEDEngine();
    }

    public static TlsCipherEngine sm4() {
        return new SM4Engine();
    }

    public static TlsCipherEngine none() {
        return NoneEngine.instance();
    }

    public static TlsCipherEngine chaCha20() {
        return new ChaCha20Engine();
    }

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
