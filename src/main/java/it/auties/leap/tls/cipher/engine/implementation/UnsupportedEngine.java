package it.auties.leap.tls.cipher.engine.implementation;

import it.auties.leap.tls.cipher.engine.TlsCipherEngine;
import it.auties.leap.tls.cipher.engine.TlsCipherEngineFactory;
import it.auties.leap.tls.exception.TlsException;

import java.nio.ByteBuffer;

public final class UnsupportedEngine extends TlsCipherEngine.Block {
    private static final UnsupportedEngine INSTANCE = new UnsupportedEngine();
    private static final TlsCipherEngineFactory FACTORY = () -> {
        throw TlsException.stub();
    };

    private UnsupportedEngine() {
        super(-1);
    }

    public static TlsCipherEngine instance() {
        return INSTANCE;
    }

    public static TlsCipherEngineFactory factory() {
        return FACTORY;
    }

    @Override
    public void cipher(ByteBuffer input, ByteBuffer output) {
        throw TlsException.stub();
    }

    @Override
    public int blockLength() {
        throw TlsException.stub();
    }
}
