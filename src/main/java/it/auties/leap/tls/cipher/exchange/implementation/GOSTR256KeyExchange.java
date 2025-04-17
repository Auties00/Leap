package it.auties.leap.tls.cipher.exchange.implementation;

import it.auties.leap.tls.cipher.exchange.TlsKeyExchange;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchangeFactory;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchangeType;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.secret.preMaster.TlsPreMasterSecretGenerator;

import java.nio.ByteBuffer;

import static it.auties.leap.tls.util.BufferUtils.writeBytes;

public sealed abstract class GOSTR256KeyExchange implements TlsKeyExchange {
    private static final TlsKeyExchangeFactory EPHEMERAL_FACTORY = new TlsKeyExchangeFactory() {
        @Override
        public TlsKeyExchange newLocalKeyExchange(TlsContext context) {
            throw new UnsupportedOperationException();
        }

        @Override
        public TlsKeyExchange newRemoteKeyExchange(TlsContext context, ByteBuffer ephemeralKeyExchangeSource) {
            throw new UnsupportedOperationException();
        }

        @Override
        public TlsKeyExchangeType type() {
            return TlsKeyExchangeType.EPHEMERAL;
        }
    };

    public static TlsKeyExchangeFactory ephemeralFactory() {
        return EPHEMERAL_FACTORY;
    }

    @Override
    public TlsKeyExchangeType type() {
        return TlsKeyExchangeType.EPHEMERAL;
    }

    @Override
    public TlsPreMasterSecretGenerator preMasterSecretGenerator() {
        return TlsPreMasterSecretGenerator.gostr256();
    }

    private static final class Client extends GOSTR256KeyExchange {
        private final byte[] encodedKeyTransport;

        public Client(byte[] encodedKeyTransport) {
            this.encodedKeyTransport = encodedKeyTransport;
        }

        @Override
        public void serialize(ByteBuffer buffer) {
            writeBytes(buffer, encodedKeyTransport);
        }

        @Override
        public int length() {
            return encodedKeyTransport.length;
        }
    }
}
