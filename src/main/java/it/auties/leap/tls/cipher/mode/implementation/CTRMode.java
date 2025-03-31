package it.auties.leap.tls.cipher.mode.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.cipher.engine.TlsCipherEngine;
import it.auties.leap.tls.cipher.engine.implementation.MagmaEngine;
import it.auties.leap.tls.cipher.exchange.TlsExchangeMac;
import it.auties.leap.tls.cipher.mode.TlsCipherMode;
import it.auties.leap.tls.cipher.mode.TlsCipherModeFactory;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.message.TlsMessage;
import it.auties.leap.tls.message.TlsMessageMetadata;

import java.nio.ByteBuffer;

public final class CTRMode extends TlsCipherMode.Block {
    private static final TlsCipherModeFactory.Block FACTORY = new TlsCipherModeFactory.Block() {
        @Override
        public TlsCipherMode newCipherMode(TlsCipherEngine.Block engine, byte[] fixedIv, TlsExchangeMac authenticator) {
            return new CTRMode(engine, fixedIv, authenticator);
        }

        @Override
        public int ivLength(TlsCipherEngine.Block engine) {
            return 4;
        }

        @Override
        public int fixedIvLength(TlsCipherEngine.Block engine) {
            return 8;
        }

        @Override
        public int tagLength() {
            return 0;
        }
    };

    private CTRMode(TlsCipherEngine engine, byte[] fixedIv, TlsExchangeMac authenticator) {
        if(!(engine instanceof MagmaEngine)) {
            throw new TlsAlert("CTR mode is supported only by Magma engines");
        }
        super(engine, fixedIv, authenticator);
    }

    public static TlsCipherModeFactory factory() {
        return FACTORY;
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
        return 8;
    }

    @Override
    public int fixedIvLength() {
        return 4;
    }

    @Override
    public int tagLength() {
        return 0;
    }
}