package it.auties.leap.tls.cipher.engine.implementation;

import it.auties.leap.tls.cipher.engine.TlsCipherEngine;
import it.auties.leap.tls.cipher.engine.TlsCipherEngineFactory;

import java.nio.ByteBuffer;

public final class NoneEngine extends TlsCipherEngine.Block {
    private static final NoneEngine INSTANCE = new NoneEngine();
    private static final TlsCipherEngineFactory FACTORY = () -> INSTANCE;

    private NoneEngine() {
        super(0);
    }

    public static TlsCipherEngineFactory factory() {
        return FACTORY;
    }

    @Override
    public void init(boolean forEncryption, byte[] key) {

    }

    @Override
    public void cipher(ByteBuffer input, ByteBuffer output) {

    }

    @Override
    public int blockLength() {
        return 0;
    }
}
