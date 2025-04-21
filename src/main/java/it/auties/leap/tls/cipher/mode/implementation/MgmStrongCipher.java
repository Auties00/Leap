package it.auties.leap.tls.cipher.mode.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
import it.auties.leap.tls.cipher.engine.TlsCipherEngine;
import it.auties.leap.tls.cipher.engine.implementation.KuznyechikEngine;
import it.auties.leap.tls.cipher.engine.implementation.MagmaEngine;
import it.auties.leap.tls.cipher.exchange.TlsExchangeMac;
import it.auties.leap.tls.cipher.mode.TlsCipher;
import it.auties.leap.tls.cipher.mode.TlsCipherFactory;
import it.auties.leap.tls.cipher.mode.TlsCipherWithEngineFactory;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.message.TlsMessageMetadata;

import java.nio.ByteBuffer;

public final class MgmStrongCipher extends TlsCipher.Block {
    private static final TlsCipherFactory FACTORY = (factory) -> new TlsCipherWithEngineFactory() {
        @Override
        public TlsCipher newCipher(boolean forEncryption, byte[] key, byte[] fixedIv, TlsExchangeMac authenticator) {
            var engine = factory.newCipherEngine(true, key);
            return new MgmStrongCipher(engine, fixedIv, authenticator);
        }

        @Override
        public int ivLength() {
            return 12;
        }

        @Override
        public int fixedIvLength() {
            return 8;
        }

        @Override
        public int tagLength() {
            return factory.blockLength();
        }
    };

    private MgmStrongCipher(TlsCipherEngine engine, byte[] fixedIv, TlsExchangeMac authenticator) {
        if(!(engine instanceof KuznyechikEngine) && !(engine instanceof MagmaEngine)) {
            throw new TlsAlert("MGM_L mode is supported only by Kuznyechik and Magma engines", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
        }
        super(engine, fixedIv, authenticator);
    }

    public static TlsCipherFactory factory() {
        return FACTORY;
    }

    @Override
    public void encrypt(byte contentType, ByteBuffer output, ByteBuffer input) {
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
        return 8;
    }

    @Override
    public int tagLength() {
        return engine().blockLength();
    }
}
