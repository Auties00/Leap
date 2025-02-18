package it.auties.leap.tls.cipher.mode;

import it.auties.leap.tls.cipher.*;
import it.auties.leap.tls.cipher.engine.KuznyechikEngine;
import it.auties.leap.tls.cipher.engine.MagmaEngine;
import it.auties.leap.tls.exception.TlsException;
import it.auties.leap.tls.mac.TlsExchangeMac;

import java.nio.ByteBuffer;

public final class CTROMacMode extends TlsCipherMode.Block {
    private static final TlsCipherModeFactory FACTORY = CTROMacMode::new;

    public CTROMacMode(TlsCipherEngine engine) {
        super(engine);
    }

    public static TlsCipherModeFactory factory() {
        return FACTORY;
    }

    @Override
    public void init(boolean forEncryption, byte[] key, byte[] fixedIv, TlsExchangeMac authenticator) {
        if(!(engine instanceof KuznyechikEngine) && !(engine instanceof MagmaEngine)) {
            throw new TlsException("CTR_OMAC mode is supported only by Kuznyechik and Magma engines");
        }
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
