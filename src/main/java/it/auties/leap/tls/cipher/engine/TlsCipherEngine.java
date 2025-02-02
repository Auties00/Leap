package it.auties.leap.tls.cipher.engine;

import it.auties.leap.tls.cipher.engine.implementation.*;
import it.auties.leap.tls.exception.TlsException;

import java.nio.ByteBuffer;
import java.util.OptionalInt;

public sealed abstract class TlsCipherEngine permits TlsCipherEngine.Block, TlsCipherEngine.Stream {
    public static TlsCipherEngine aes() {
        return new AESEngine();
    }

    public static TlsCipherEngine aria() {
        return new ARIAEngine();
    }
    
    public static TlsCipherEngine camellia() {
        return new CamelliaEngine();
    }

    public static TlsCipherEngine des() {
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
        return NoneEngine.instance();
    }

    public static TlsCipherEngine chaCha20() {
        return new ChaCha20Engine();
    }

    protected byte[] key;
    protected boolean forEncryption;
    protected boolean initialized;

    private TlsCipherEngine() {
        
    }
    
    public void init(boolean forEncryption, byte[] key) {
        if(initialized) {
            throw new TlsException("Engine is already initialized");
        }

        this.forEncryption = forEncryption;
        this.key = key;
        this.initialized = true;
    }

    public abstract void update(ByteBuffer input, ByteBuffer output);

    public byte[] key() {
        return key;
    }

    public int keyLength() {
        return key.length;
    }
    
    public OptionalInt exportedKeyLength() {
        return OptionalInt.empty();
    }

    public boolean forEncryption() {
        return forEncryption;
    }

    public static abstract non-sealed class Block extends TlsCipherEngine {
        protected Block() {
            
        }

        public abstract int blockLength();
    }

    public static abstract non-sealed class Stream extends TlsCipherEngine {
        protected Stream() {
            
        }
    }
}
