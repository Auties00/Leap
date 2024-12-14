package it.auties.leap.tls.crypto.cipher.engine;

import it.auties.leap.tls.TlsCipher;

import java.nio.ByteBuffer;

public sealed abstract class TlsCipherEngine permits TlsCipherEngine.Stream, TlsCipherEngine.Block {
    final boolean forEncryption;
    final byte[] key;
    TlsCipherEngine(boolean forEncryption, byte[] key) {
        this.forEncryption = forEncryption;
        this.key = key;
    }

    public boolean forEncryption() {
        return forEncryption;
    }

    public byte[] key() {
        return key;
    }

    public static TlsCipherEngine of(
            TlsCipher cipher,
            boolean forEncryption,
            byte[] key
    ) {
        return switch (cipher.type().engine()) {
            case NULL -> throw new InternalError("Unexpected call with NULL cipher engine");
            case AES -> new AESEngine(forEncryption, key);
            case ARIA -> new ARIAEngine(forEncryption, key);
            case CAMELLIA -> new CamelliaEngine(forEncryption, key);
            case DES -> new DESEngine(forEncryption, key);
            case IDEA -> new IDEAEngine(forEncryption, key);
            case KUZNYECHIK -> new KuznyechikEngine(forEncryption, key);
            case MAGMA -> new MagmaEngine(forEncryption, key);
            case RC2 -> new RC2Engine(forEncryption, key);
            case RC4 -> new RC4Engine(forEncryption, key);
            case SEED -> new SEEDEngine(forEncryption, key);
            case SM4 -> new SM4Engine(forEncryption, key);
            case DES_EDE -> new DESedeEngine(forEncryption, key);
            case CHACHA20 -> new ChaCha20Engine(forEncryption, key);
        };
    }
    
    public abstract void process(ByteBuffer input, ByteBuffer output);
    public abstract void reset();

    public static abstract sealed class Stream extends TlsCipherEngine permits ChaCha20Engine, RC4Engine {
        boolean initialized;
        Stream(boolean forEncryption, byte[] key) {
            super(forEncryption, key);
        }

        public void init(byte[] iv) {
            this.initialized = true;
        }
    }

    public static abstract sealed class Block extends TlsCipherEngine permits AESEngine, ARIAEngine, CamelliaEngine, DESEngine, MagmaEngine, IDEAEngine, KuznyechikEngine, RC2Engine, SEEDEngine, SM4Engine {
        Block(boolean forEncryption, byte[] key) {
            super(forEncryption, key);
        }

        public abstract int blockSize();
    }
}
