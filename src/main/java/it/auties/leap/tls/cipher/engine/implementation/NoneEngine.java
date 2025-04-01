package it.auties.leap.tls.cipher.engine.implementation;

import it.auties.leap.tls.cipher.engine.TlsCipherEngine;
import it.auties.leap.tls.cipher.engine.TlsCipherEngineFactory;

import java.nio.ByteBuffer;

public final class NoneEngine extends TlsCipherEngine.Block {
    private static final NoneEngine INSTANCE_CIPHER = new NoneEngine(false);
    private static final NoneEngine INSTANCE_DECIPHER = new NoneEngine(true);
    private static final TlsCipherEngineFactory FACTORY = new TlsCipherEngineFactory() {
        @Override
        public TlsCipherEngine newCipherEngine(boolean forEncryption, byte[] key) {
            return forEncryption ? INSTANCE_CIPHER : INSTANCE_DECIPHER;
        }

        @Override
        public int keyLength() {
            return 0;
        }

        @Override
        public int blockLength() {
            return 0;
        }
    };

    private NoneEngine(boolean forEncryption) {
        super(forEncryption);
    }

    public static TlsCipherEngineFactory factory() {
        return FACTORY;
    }

    @Override
    public void cipher(ByteBuffer input, ByteBuffer output) {

    }

    @Override
    public int blockLength() {
        return 0;
    }
}
