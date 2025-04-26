package it.auties.leap.tls.ciphersuite.exchange.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
import it.auties.leap.tls.ciphersuite.exchange.TlsKeyExchange;
import it.auties.leap.tls.ciphersuite.exchange.TlsKeyExchangeFactory;
import it.auties.leap.tls.ciphersuite.exchange.TlsKeyExchangeType;
import it.auties.leap.tls.connection.TlsConnectionSecret;
import it.auties.leap.tls.context.TlsContext;

import java.nio.ByteBuffer;
import java.util.Optional;

public final class ContextualKeyExchange implements TlsKeyExchange {
    private static final TlsKeyExchangeFactory EPHEMERAL_FACTORY = new TlsKeyExchangeFactory() {
        @Override
        public TlsKeyExchange newLocalKeyExchange(TlsContext context) {
            return INSTANCE;
        }

        @Override
        public TlsKeyExchange newRemoteKeyExchange(TlsContext context, ByteBuffer source) {
            if(source != null) {
                throw new TlsAlert("Contextual key exchange doesn't take an ephemeral key exchange source", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
            }

            return INSTANCE;
        }

        @Override
        public TlsKeyExchangeType type() {
            return TlsKeyExchangeType.EPHEMERAL;
        }
    };

    public static TlsKeyExchangeFactory ephemeralFactory() {
        return EPHEMERAL_FACTORY;
    }

    private static final ContextualKeyExchange INSTANCE = new ContextualKeyExchange();
    private ContextualKeyExchange() {

    }

    @Override
    public TlsKeyExchangeType type() {
        return TlsKeyExchangeType.EPHEMERAL;
    }

    // TLS 1.3 doesn't use a pre shared secret
    @Override
    public Optional<TlsConnectionSecret> generatePreSharedSecret(TlsContext context) {
        return Optional.empty();
    }

    @Override
    public void serialize(ByteBuffer buffer) {
        System.out.println("Should i be called?");
    }

    @Override
    public int length() {
        return 0;
    }
}
