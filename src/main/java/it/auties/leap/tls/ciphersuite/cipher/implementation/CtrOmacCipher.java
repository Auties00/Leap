package it.auties.leap.tls.ciphersuite.cipher.implementation;

import it.auties.leap.tls.ciphersuite.engine.TlsCipherEngine;
import it.auties.leap.tls.ciphersuite.exchange.TlsExchangeMac;
import it.auties.leap.tls.ciphersuite.cipher.TlsCipher;
import it.auties.leap.tls.ciphersuite.cipher.TlsCipherFactory;
import it.auties.leap.tls.ciphersuite.cipher.TlsCipherWithEngineFactory;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.message.TlsMessageMetadata;

import java.nio.ByteBuffer;

public final class CtrOmacCipher extends TlsCipher.Block {
    private static final TlsCipherFactory FACTORY = (factory) -> new TlsCipherWithEngineFactory() {
        @Override
        public TlsCipher newCipher(boolean forEncryption, byte[] key, byte[] fixedIv, TlsExchangeMac authenticator) {
            var engine = factory.newCipherEngine(forEncryption, key);
            return new CtrOmacCipher(engine, fixedIv, authenticator);
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

    private CtrOmacCipher(TlsCipherEngine engine, byte[] fixedIv, TlsExchangeMac authenticator) {
        super(engine, fixedIv, authenticator);
    }

    public static TlsCipherFactory factory() {
        return FACTORY;
    }

    @Override
    public void encrypt(byte contentType, ByteBuffer input, ByteBuffer output) {
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
