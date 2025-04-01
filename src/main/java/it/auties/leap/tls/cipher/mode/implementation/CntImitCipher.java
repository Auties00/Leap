package it.auties.leap.tls.cipher.mode.implementation;

import it.auties.leap.tls.cipher.engine.TlsCipherEngine;
import it.auties.leap.tls.cipher.engine.implementation.KuznyechikEngine;
import it.auties.leap.tls.cipher.engine.implementation.MagmaEngine;
import it.auties.leap.tls.cipher.mode.TlsCipher;
import it.auties.leap.tls.cipher.mode.TlsCipherFactory;
import it.auties.leap.tls.cipher.mode.TlsCipherWithEngineFactory;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.cipher.exchange.TlsExchangeMac;
import it.auties.leap.tls.message.TlsMessage;
import it.auties.leap.tls.message.TlsMessageMetadata;

import java.nio.ByteBuffer;

public final class CntImitCipher extends TlsCipher.Block {
    private static final TlsCipherFactory FACTORY = (factory) -> new TlsCipherWithEngineFactory() {
        @Override
        public TlsCipher newCipher(boolean forEncryption, byte[] key, byte[] fixedIv, TlsExchangeMac authenticator) {
            var engine = factory.newCipherEngine(forEncryption, key);
            return new CntImitCipher(engine, fixedIv, authenticator);
        }

        @Override
        public int ivLength() {
            return factory.blockLength() / 2;
        }

        @Override
        public int fixedIvLength() {
            return factory.blockLength() / 2;
        }

        @Override
        public int tagLength() {
            return 0;
        }
    };

    private CntImitCipher(TlsCipherEngine engine, byte[] fixedIv, TlsExchangeMac authenticator) {
        if(!(engine instanceof KuznyechikEngine) && !(engine instanceof MagmaEngine)) {
            throw new TlsAlert("CNT_IMIT mode is supported only by Kuznyechik and Magma engines");
        }
        super(engine, fixedIv, authenticator);
    }

    public static TlsCipherFactory factory() {
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
        return engine().blockLength() / 2;
    }

    @Override
    public int fixedIvLength() {
        return engine().blockLength() / 2;
    }

    @Override
    public int tagLength() {
        return 0;
    }
}
