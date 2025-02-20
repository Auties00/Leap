package it.auties.leap.tls.cipher.mode.implementation;

import it.auties.leap.tls.cipher.engine.TlsCipherEngine;
import it.auties.leap.tls.cipher.engine.implementation.KuznyechikEngine;
import it.auties.leap.tls.cipher.engine.implementation.MagmaEngine;
import it.auties.leap.tls.cipher.mode.TlsCipherIV;
import it.auties.leap.tls.cipher.mode.TlsCipherMode;
import it.auties.leap.tls.cipher.mode.TlsCipherModeFactory;
import it.auties.leap.tls.exception.TlsException;
import it.auties.leap.tls.mac.TlsExchangeMac;

import java.nio.ByteBuffer;

public final class CNTImitMode extends TlsCipherMode.Block {
    private static final TlsCipherModeFactory FACTORY = CNTImitMode::new;

    public static TlsCipherModeFactory factory() {
        return FACTORY;
    }

    public CNTImitMode(TlsCipherEngine engine) {
        if(!(engine instanceof KuznyechikEngine) && !(engine instanceof MagmaEngine)) {
            throw new TlsException("CNT_IMIT mode is supported only by Kuznyechik and Magma engines");
        }
        super(engine);
    }

    @Override
    public void init(boolean forEncryption, byte[] key, byte[] fixedIv, TlsExchangeMac authenticator) {
        super.init(forEncryption, key, fixedIv, authenticator);
    }

    @Override
    public void cipher(byte contentType, ByteBuffer input, ByteBuffer output, byte[] sequence) {
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
