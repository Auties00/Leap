package it.auties.leap.tls.cipher.exchange.factory.implementation;

import it.auties.leap.tls.cipher.exchange.factory.TlsKeyExchangeFactory;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchange;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchangeType;

import java.nio.ByteBuffer;

public class SRPKeyExchangeFactory implements TlsKeyExchangeFactory {
    private static final SRPKeyExchangeFactory EPHEMERAL_FACTORY = new SRPKeyExchangeFactory();

    private SRPKeyExchangeFactory() {

    }

    public static SRPKeyExchangeFactory ephemeralFactory() {
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
