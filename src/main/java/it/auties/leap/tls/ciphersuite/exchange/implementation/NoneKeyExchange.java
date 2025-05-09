package it.auties.leap.tls.ciphersuite.exchange.implementation;

import it.auties.leap.tls.ciphersuite.exchange.TlsKeyExchange;
import it.auties.leap.tls.ciphersuite.exchange.TlsKeyExchangeFactory;
import it.auties.leap.tls.ciphersuite.exchange.TlsKeyExchangeType;
import it.auties.leap.tls.connection.TlsConnectionSecret;
import it.auties.leap.tls.context.TlsContext;

import java.nio.ByteBuffer;
import java.util.Optional;

import static it.auties.leap.tls.util.BufferUtils.writeBytes;

public sealed abstract class NoneKeyExchange implements TlsKeyExchange {
    private static final TlsKeyExchangeFactory EPHEMERAL_FACTORY = new TlsKeyExchangeFactory() {
        @Override
        public Optional<TlsKeyExchange> newLocalKeyExchange(TlsContext context) {
            throw new UnsupportedOperationException();
        }

        @Override
        public Optional<TlsKeyExchange> newRemoteKeyExchange(TlsContext context, ByteBuffer source) {
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
    public TlsConnectionSecret generatePreSharedSecret(TlsContext context) {
        throw new UnsupportedOperationException();
    }

    private static final class Client extends NoneKeyExchange {
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
