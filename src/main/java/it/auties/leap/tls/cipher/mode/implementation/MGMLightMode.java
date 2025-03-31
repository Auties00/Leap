package it.auties.leap.tls.cipher.mode.implementation;

import it.auties.leap.tls.cipher.engine.TlsCipherEngine;
import it.auties.leap.tls.cipher.engine.implementation.KuznyechikEngine;
import it.auties.leap.tls.cipher.engine.implementation.MagmaEngine;
import it.auties.leap.tls.cipher.mode.TlsCipherMode;
import it.auties.leap.tls.cipher.mode.TlsCipherModeFactory;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.cipher.exchange.TlsExchangeMac;
import it.auties.leap.tls.message.TlsMessage;
import it.auties.leap.tls.message.TlsMessageMetadata;

import java.nio.ByteBuffer;

public final class MGMLightMode extends TlsCipherMode.Block {
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
            return engine.blockLength() - fixedIv.length;
        }

        @Override
        public int tagLength(TlsCipherEngine.Block engine) {
            return engine.blockLength();
        }
    };
    private MGMLightMode(TlsCipherEngine engine) {
        if(!(engine instanceof KuznyechikEngine) && !(engine instanceof MagmaEngine)) {
            throw new TlsAlert("MGM_L mode is supported only by Kuznyechik and Magma engines");
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
        return engine().blockLength();
    }

    @Override
    public int fixedIvLength() {
        return engine().blockLength() - fixedIv.length;
    }

    @Override
    public int tagLength() {
        return engine().blockLength();
    }
}
