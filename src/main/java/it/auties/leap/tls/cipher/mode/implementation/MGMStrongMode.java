package it.auties.leap.tls.cipher.mode.implementation;

import it.auties.leap.tls.cipher.TlsCipherIV;
import it.auties.leap.tls.cipher.engine.TlsCipherEngine;
import it.auties.leap.tls.cipher.mode.TlsCipherMode;
import it.auties.leap.tls.cipher.mode.TlsCipherModeFactory;
import it.auties.leap.tls.cipher.auth.TlsExchangeAuthenticator;

import java.nio.ByteBuffer;

public final class MGMStrongMode extends TlsCipherMode.Block {
    private static final TlsCipherModeFactory FACTORY = MGMStrongMode::new;

    public static TlsCipherModeFactory factory() {
        return FACTORY;
    }

    @Override
    public void init(TlsExchangeAuthenticator authenticator, TlsCipherEngine engine, byte[] fixedIv) {
        super.init(authenticator, engine, fixedIv);
    }

    @Override
    public void update(byte contentType, ByteBuffer input, ByteBuffer output, byte[] sequence) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void doFinal(byte contentType, ByteBuffer input, ByteBuffer output) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void reset() {
        throw new UnsupportedOperationException();
    }

    @Override
    public TlsCipherIV ivLength() {
        var blockLength = engine().blockLength();
        return new TlsCipherIV(blockLength, blockLength - fixedIv.length);
    }

    @Override
    public int tagLength() {
        return engine().blockLength();
    }
}
