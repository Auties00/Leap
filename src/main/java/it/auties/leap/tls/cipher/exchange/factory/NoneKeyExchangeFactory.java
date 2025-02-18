package it.auties.leap.tls.cipher.exchange.factory;

import it.auties.leap.tls.TlsContext;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchange;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchangeFactory;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchangeType;
import it.auties.leap.tls.cipher.exchange.client.NoneClientKeyExchange;
import it.auties.leap.tls.cipher.exchange.server.NoneServerKeyExchange;
import it.auties.leap.tls.exception.TlsException;

import java.nio.ByteBuffer;

public class NoneKeyExchangeFactory implements TlsKeyExchangeFactory {
    private static final NoneKeyExchangeFactory EPHEMERAL_FACTORY = new NoneKeyExchangeFactory();

    private NoneKeyExchangeFactory() {

    }

    public static NoneKeyExchangeFactory ephemeralFactory() {
        return EPHEMERAL_FACTORY;
    }

    @Override
    public TlsKeyExchange newLocalKeyExchange(TlsContext context) {
        return getClient(context);
    }

    @Override
    public TlsKeyExchange decodeRemoteKeyExchange(TlsContext context, ByteBuffer buffer) {
        if(buffer.hasRemaining()) {
            throw new TlsException("Expected empty buffer");
        }

        return getServer(context);
    }

    private TlsKeyExchange getClient(TlsContext context) {
        return switch (context.selectedMode().orElseThrow(() -> new TlsException("No mode was selected"))) {
            case CLIENT -> NoneClientKeyExchange.instance();
            case SERVER -> NoneServerKeyExchange.instance();
        };
    }

    private TlsKeyExchange getServer(TlsContext context) {
        return switch (context.selectedMode().orElseThrow(() -> new TlsException("No mode was selected"))) {
            case SERVER -> NoneClientKeyExchange.instance();
            case CLIENT -> NoneServerKeyExchange.instance();
        };
    }

    @Override
    public TlsKeyExchangeType type() {
        return TlsKeyExchangeType.EPHEMERAL;
    }
}
