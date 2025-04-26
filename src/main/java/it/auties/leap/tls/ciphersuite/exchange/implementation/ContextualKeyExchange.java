package it.auties.leap.tls.ciphersuite.exchange.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
import it.auties.leap.tls.ciphersuite.exchange.TlsKeyExchange;
import it.auties.leap.tls.ciphersuite.exchange.TlsKeyExchangeFactory;
import it.auties.leap.tls.ciphersuite.exchange.TlsKeyExchangeType;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.secret.TlsPreMasterSecretGenerator;

import java.nio.ByteBuffer;

// TODO: Implement contextual TLS 1.3 key exchange
public final class ContextualKeyExchange implements TlsKeyExchange {
    private static final TlsKeyExchangeFactory EPHEMERAL_FACTORY = new TlsKeyExchangeFactory() {
        @Override
        public TlsKeyExchange newLocalKeyExchange(TlsContext context) {
            return INSTANCE;
        }

        @Override
        public TlsKeyExchange newRemoteKeyExchange(TlsContext context, ByteBuffer ephemeralKeyExchangeSource) {
            if(ephemeralKeyExchangeSource != null) {
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

    @Override
    public TlsPreMasterSecretGenerator preMasterSecretGenerator() {
        return TlsPreMasterSecretGenerator.contextual();
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
