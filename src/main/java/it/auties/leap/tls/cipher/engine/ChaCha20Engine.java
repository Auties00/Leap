package it.auties.leap.tls.cipher.engine;

import it.auties.leap.tls.cipher.TlsCipherEngine;
import it.auties.leap.tls.cipher.TlsCipherEngineFactory;

import java.nio.ByteBuffer;

public class ChaCha20Engine extends TlsCipherEngine.Stream {
    private static final TlsCipherEngineFactory FACTORY = ChaCha20Engine::new;

    public ChaCha20Engine() {
        super(32);
    }

    @Override
    public void init(boolean forEncryption, byte[] key) {
        super.init(forEncryption, key);
    }

    public static TlsCipherEngineFactory factory() {
        return FACTORY;
    }

    @Override
    public void update(ByteBuffer input, ByteBuffer output) {
        throw new UnsupportedOperationException();
    }
}
