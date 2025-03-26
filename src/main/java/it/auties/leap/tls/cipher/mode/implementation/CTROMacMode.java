package it.auties.leap.tls.cipher.mode.implementation;

import it.auties.leap.tls.cipher.engine.TlsCipherEngine;
import it.auties.leap.tls.cipher.engine.implementation.KuznyechikEngine;
import it.auties.leap.tls.cipher.engine.implementation.MagmaEngine;
import it.auties.leap.tls.cipher.mode.TlsCipherMode;
import it.auties.leap.tls.cipher.mode.TlsCipherModeFactory;
import it.auties.leap.tls.TlsContext;
import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.mac.TlsExchangeMac;
import it.auties.leap.tls.message.TlsMessage;
import it.auties.leap.tls.message.TlsMessageMetadata;

import java.nio.ByteBuffer;

public final class CTROMacMode extends TlsCipherMode.Block {
    private static final TlsCipherModeFactory FACTORY = CTROMacMode::new;

    private CTROMacMode(TlsCipherEngine engine) {
        if(!(engine instanceof KuznyechikEngine) && !(engine instanceof MagmaEngine)) {
            throw new TlsAlert("CTR_OMAC mode is supported only by Kuznyechik and Magma engines");
        }
        super(engine);
    }

    public static TlsCipherModeFactory factory() {
        return FACTORY;
    }

    @Override
    public void init(boolean forEncryption, byte[] key, byte[] fixedIv, TlsExchangeMac authenticator) {
        super.init(forEncryption, key, fixedIv, authenticator);
    }

    @Override
    public void encrypt(TlsContext context, TlsMessage message, ByteBuffer output) {
        throw new UnsupportedOperationException();
    }

    @Override
    public ByteBuffer decrypt(TlsContext context, TlsMessageMetadata metadata, ByteBuffer input) {
        throw new UnsupportedOperationException();
    }

    @Override
    public int ivLength() {
        return switch (engine) {
            case KuznyechikEngine _ -> 8;
            case MagmaEngine _ -> 4;
            default -> throw new InternalError("Init check failed");
        };
    }

    @Override
    public int fixedIvLength() {
        return switch (engine) {
            case KuznyechikEngine _ -> 8;
            case MagmaEngine _ -> 4;
            default -> throw new InternalError("Init check failed");
        };
    }

    @Override
    public int tagLength() {
        return 0;
    }
}
