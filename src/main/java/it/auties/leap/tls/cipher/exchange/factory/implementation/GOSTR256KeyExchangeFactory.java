package it.auties.leap.tls.cipher.exchange.factory.implementation;

import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchange;
import it.auties.leap.tls.cipher.exchange.factory.TlsKeyExchangeFactory;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchangeType;

import java.nio.ByteBuffer;

public class GOSTR256KeyExchangeFactory implements TlsKeyExchangeFactory {
    private static final GOSTR256KeyExchangeFactory EPHEMERAL_FACTORY = new GOSTR256KeyExchangeFactory();

    private GOSTR256KeyExchangeFactory() {

    }

    public static GOSTR256KeyExchangeFactory ephemeralFactory() {
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
