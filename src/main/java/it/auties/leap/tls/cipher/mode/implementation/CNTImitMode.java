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

public final class CNTImitMode extends TlsCipherMode.Block {
    private static final TlsCipherModeFactory.Block FACTORY = new TlsCipherModeFactory.Block() {
        @Override
        public TlsCipherMode newCipherMode(TlsCipherEngine.Block engine, byte[] fixedIv, TlsExchangeMac authenticator) {
            return new CNTImitMode(engine, fixedIv, authenticator);
        }

        @Override
        public int ivLength(TlsCipherEngine.Block engine) {
            return switch (engine) {
                case KuznyechikEngine _ -> 8;
                case MagmaEngine _ -> 4;
                default -> throw new InternalError("Init check failed");
            };
        }

        @Override
        public int fixedIvLength(TlsCipherEngine.Block engine) {
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
    };

    private CNTImitMode(TlsCipherEngine engine, byte[] fixedIv, TlsExchangeMac authenticator) {
        if(!(engine instanceof KuznyechikEngine) && !(engine instanceof MagmaEngine)) {
            throw new TlsAlert("CNT_IMIT mode is supported only by Kuznyechik and Magma engines");
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
