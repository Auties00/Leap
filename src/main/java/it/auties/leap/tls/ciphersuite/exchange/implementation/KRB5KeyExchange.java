package it.auties.leap.tls.ciphersuite.exchange.implementation;

import it.auties.leap.tls.ciphersuite.exchange.TlsKeyExchange;
import it.auties.leap.tls.ciphersuite.exchange.TlsKeyExchangeFactory;
import it.auties.leap.tls.ciphersuite.exchange.TlsKeyExchangeType;
import it.auties.leap.tls.connection.TlsConnectionSecret;
import it.auties.leap.tls.context.TlsContext;

import java.nio.ByteBuffer;
import java.util.Optional;

import static it.auties.leap.tls.util.BufferUtils.*;

public sealed abstract class KRB5KeyExchange implements TlsKeyExchange {
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

    private static final class Client extends KRB5KeyExchange {
        private final byte[] ticket;
        private final byte[] authenticator;
        private final byte[] encryptedPreMasterSecret;

        private Client(byte[] ticket, byte[] authenticator, byte[] encryptedPreMasterSecret) {
            this.ticket = ticket;
            this.authenticator = authenticator;
            this.encryptedPreMasterSecret = encryptedPreMasterSecret;
        }

        private Client(ByteBuffer buffer) {
            this.ticket = readBytesBigEndian16(buffer);
            this.authenticator = readBytesBigEndian16(buffer);
            this.encryptedPreMasterSecret = readBytesBigEndian16(buffer);
        }

        @Override
        public void serialize(ByteBuffer buffer) {
            writeBytesBigEndian16(buffer, ticket);
            writeBytesBigEndian16(buffer, authenticator);
            writeBytesBigEndian16(buffer, encryptedPreMasterSecret);
        }

        @Override
        public int length() {
            return INT16_LENGTH + ticket.length
                    + INT16_LENGTH + authenticator.length
                    + INT16_LENGTH + encryptedPreMasterSecret.length;
        }
    }
}
