package it.auties.leap.tls.ciphersuite.exchange.implementation;

import it.auties.leap.tls.ciphersuite.exchange.TlsKeyExchange;
import it.auties.leap.tls.ciphersuite.exchange.TlsKeyExchangeFactory;
import it.auties.leap.tls.ciphersuite.exchange.TlsKeyExchangeType;
import it.auties.leap.tls.connection.TlsConnectionSecret;
import it.auties.leap.tls.context.TlsContext;

import java.nio.ByteBuffer;
import java.util.Optional;

import static it.auties.leap.tls.util.BufferUtils.*;

public sealed abstract class PSKKeyExchange implements TlsKeyExchange {
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

    private static final class Client extends PSKKeyExchange {
        private final byte[] identityKey;

        private Client(byte[] identityKey) {
            this.identityKey = identityKey;
        }

        private Client(ByteBuffer buffer) {
            this.identityKey = readBytesBigEndian16(buffer);
        }

        @Override
        public void serialize(ByteBuffer buffer) {
            writeBytesBigEndian16(buffer, identityKey);
        }

        @Override
        public int length() {
            return INT16_LENGTH + identityKey.length;
        }
    }

    private static final class Server extends PSKKeyExchange {
        private final byte[] identityKeyHint;

        private Server(byte[] identityKeyHint) {
            this.identityKeyHint = identityKeyHint;
        }

        private Server(ByteBuffer buffer) {
            this(readBytesBigEndian16(buffer));
        }

        @Override
        public void serialize(ByteBuffer buffer) {
            writeBytesBigEndian16(buffer, identityKeyHint);
        }

        @Override
        public int length() {
            return INT16_LENGTH + identityKeyHint.length;
        }
    }
}
