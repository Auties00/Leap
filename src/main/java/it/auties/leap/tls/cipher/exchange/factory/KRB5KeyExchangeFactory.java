package it.auties.leap.tls.cipher.exchange.factory;

import it.auties.leap.tls.TlsContext;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchange;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchangeFactory;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchangeType;

import java.nio.ByteBuffer;

public class KRB5KeyExchangeFactory implements TlsKeyExchangeFactory {
    private static final KRB5KeyExchangeFactory EPHEMERAL_FACTORY = new KRB5KeyExchangeFactory();

    private KRB5KeyExchangeFactory() {

    }

    public static KRB5KeyExchangeFactory ephemeralFactory() {
        return EPHEMERAL_FACTORY;
    }

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
}
