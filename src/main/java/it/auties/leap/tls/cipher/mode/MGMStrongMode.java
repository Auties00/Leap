package it.auties.leap.tls.cipher.mode;

import it.auties.leap.tls.cipher.*;

import java.nio.ByteBuffer;

public final class MGMStrongMode extends TlsCipherMode.Block {
    private static final TlsCipherModeFactory FACTORY = MGMStrongMode::new;

    public MGMStrongMode(TlsCipherEngine engine) {
        super(engine);
    }

    public static TlsCipherModeFactory factory() {
        return FACTORY;
    }

    @Override
    public void init(boolean forEncryption, byte[] key, byte[] fixedIv, TlsExchangeAuthenticator authenticator) {
        super.init(forEncryption, key, fixedIv, authenticator);
    }

    @Override
    public void cipher(byte contentType, ByteBuffer input, ByteBuffer output, byte[] sequence) {
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
