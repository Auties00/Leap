package it.auties.leap.tls.cipher.mode;

import it.auties.leap.tls.cipher.*;
import it.auties.leap.tls.cipher.engine.KuznyechikEngine;
import it.auties.leap.tls.cipher.engine.MagmaEngine;
import it.auties.leap.tls.exception.TlsException;

import java.nio.ByteBuffer;

public final class CNTImitMode extends TlsCipherMode.Block {
    private static final TlsCipherModeFactory FACTORY = CNTImitMode::new;

    public static TlsCipherModeFactory factory() {
        return FACTORY;
    }

    public CNTImitMode(TlsCipherEngine engine) {
        super(engine);
    }

    @Override
    public void init(TlsExchangeAuthenticator authenticator, byte[] fixedIv) {
        if(!(engine instanceof KuznyechikEngine) && !(engine instanceof MagmaEngine)) {
            throw new TlsException("CNT_IMIT mode is supported only by Kuznyechik and Magma engines");
        }
        super.init(authenticator, fixedIv);
    }

    @Override
    public void update(byte contentType, ByteBuffer input, ByteBuffer output, byte[] sequence) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void reset() {
        throw new UnsupportedOperationException();
    }

    @Override
    public TlsCipherIV ivLength() {
        return switch (engine) {
            case KuznyechikEngine _ -> new TlsCipherIV(8, 8);
            case MagmaEngine _ -> new TlsCipherIV(4, 4);
            default -> throw new InternalError("Init check failed");
        };
    }

    @Override
    public int tagLength() {
        return 0;
    }
}
