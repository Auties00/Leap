package it.auties.leap.tls.cipher.exchange.implementation;

import it.auties.leap.tls.cipher.exchange.TlsKeyExchange;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchangeFactory;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchangeType;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsContextMode;
import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.secret.TlsPreMasterSecretGenerator;

import java.nio.ByteBuffer;

// TODO: Implement contextual TLS 1.3 key exchange
public sealed abstract class ContextualKeyExchange implements TlsKeyExchange {
    private static final TlsKeyExchangeFactory EPHEMERAL_FACTORY = new TlsKeyExchangeFactory() {
        @Override
        public TlsKeyExchange newLocalKeyExchange(TlsContext context) {
            return switch (getMode(context)) {
                case CLIENT -> Client.instance();
                case SERVER -> Server.instance();
            };
        }

        @Override
        public TlsKeyExchange decodeRemoteKeyExchange(TlsContext context, ByteBuffer buffer) {
            if(buffer.hasRemaining()) {
                throw new TlsAlert("Expected empty buffer");
            }

            return switch (getMode(context)) {
                case SERVER -> Server.instance();
                case CLIENT -> Client.instance();
            };
        }

        private TlsContextMode getMode(TlsContext context) {
            return context.selectedMode()
                    .orElseThrow(TlsAlert::noModeSelected);
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
        return TlsPreMasterSecretGenerator.contextual();
    }

    private static final class Client extends ContextualKeyExchange {
        private static final Client INSTANCE = new Client();

        private Client() {

        }

        public static Client instance() {
            return INSTANCE;
        }

        @Override
        public void serialize(ByteBuffer buffer) {

        }

        @Override
        public int length() {
            return 0;
        }
    }

    private static final class Server extends ContextualKeyExchange {
        private static final Server INSTANCE = new Server();

        private Server() {

        }

        public static Server instance() {
            return INSTANCE;
        }

        @Override
        public void serialize(ByteBuffer buffer) {

        }

        @Override
        public int length() {
            return 0;
        }
    }
}
