package it.auties.leap.tls.cipher.exchange.implementation;

import it.auties.leap.tls.cipher.exchange.TlsKeyExchange;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchangeFactory;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchangeType;
import it.auties.leap.tls.TlsContext;
import it.auties.leap.tls.secret.TlsPreMasterSecretGenerator;

import java.nio.ByteBuffer;

import static it.auties.leap.tls.util.BufferUtils.*;

public sealed abstract class KRB5KeyExchange implements TlsKeyExchange {
    private static final TlsKeyExchangeFactory EPHEMERAL_FACTORY = new TlsKeyExchangeFactory() {
        @Override
        public TlsKeyExchange newLocalKeyExchange(TlsContext context) {
            throw new UnsupportedOperationException();
        }

        @Override
        public TlsKeyExchange decodeRemoteKeyExchange(TlsContext context, ByteBuffer buffer) {
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
        return TlsPreMasterSecretGenerator.krb5();
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
