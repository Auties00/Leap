package it.auties.leap.tls.cipher.engine;

import it.auties.leap.tls.cipher.TlsCipherEngine;
import it.auties.leap.tls.cipher.TlsCipherEngineFactory;

import java.nio.ByteBuffer;

public final class NoneEngine extends TlsCipherEngine.Block {
    private static final NoneEngine INSTANCE = new NoneEngine();
    private static final TlsCipherEngineFactory FACTORY = () -> INSTANCE;

    private NoneEngine() {
        super(0);
    }

    public static NoneEngine instance() {
        return INSTANCE;
    }

    public static TlsCipherEngineFactory factory() {
        return FACTORY;
    }

    @Override
    public void init(boolean forEncryption, byte[] key) {

    }

    @Override
    public void update(ByteBuffer input, ByteBuffer output) {

    }

    @Override
    public int blockLength() {
        return 0;
    }
}
