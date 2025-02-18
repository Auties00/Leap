package it.auties.leap.tls.cipher.exchange.factory;

import it.auties.leap.tls.TlsContext;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchange;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchangeFactory;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchangeType;
import it.auties.leap.tls.cipher.exchange.client.ECDHClientKeyExchange;
import it.auties.leap.tls.cipher.exchange.server.ECDHServerKeyExchange;
import it.auties.leap.tls.exception.TlsException;

import java.nio.ByteBuffer;
import java.util.NoSuchElementException;

public class ECDHKeyExchangeFactory implements TlsKeyExchangeFactory {
    private static final ECDHKeyExchangeFactory STATIC = new ECDHKeyExchangeFactory(TlsKeyExchangeType.STATIC);
    private static final ECDHKeyExchangeFactory EPHEMERAL = new ECDHKeyExchangeFactory(TlsKeyExchangeType.EPHEMERAL);

    private final TlsKeyExchangeType type;

    private ECDHKeyExchangeFactory(TlsKeyExchangeType type) {
        this.type = type;
    }

    public static ECDHKeyExchangeFactory staticFactory() {
        return STATIC;
    }

    public static ECDHKeyExchangeFactory ephemeralFactory() {
        return EPHEMERAL;
    }

    @Override
    public TlsKeyExchange newLocalKeyExchange(TlsContext context) {
        return switch (context.selectedMode().orElseThrow(() -> new TlsException("No mode was selected"))) {
            case CLIENT -> newClientKeyExchange(context);
            case SERVER -> newServerKeyExchange(context);
        };
    }

    @Override
    public TlsKeyExchange decodeRemoteKeyExchange(TlsContext context, ByteBuffer buffer) {
        return switch (context.selectedMode().orElseThrow(() -> new TlsException("No mode was selected"))) {
            case SERVER -> new ECDHClientKeyExchange(type, buffer);
            case CLIENT -> new ECDHServerKeyExchange(type, buffer, context.localSupportedGroups());
        };
    }

    private ECDHClientKeyExchange newClientKeyExchange(TlsContext context) {
        var group = context.remoteKeyExchange()
                .map(entry -> entry instanceof ECDHServerKeyExchange serverKeyExchange ? serverKeyExchange : null)
                .orElseThrow(() -> new TlsException("Missing remote ECDH key exchange"))
                .parameters()
                .toGroup(context);
        var keyPair = group.generateLocalKeyPair(context);
        context.setLocalKeyPair(keyPair);
        return new ECDHClientKeyExchange(type, group.dumpLocalPublicKey(context));
    }

    private ECDHServerKeyExchange newServerKeyExchange(TlsContext context) {
        var group = context.localPreferredEllipticCurve()
                .orElseThrow(() -> new NoSuchElementException("No supported group is an elliptic curve"));
        var keyPair = group.generateLocalKeyPair(context);
        context.setLocalKeyPair(keyPair);
        return new ECDHServerKeyExchange(type, group.toParameters(), group.dumpLocalPublicKey(context));
    }

    @Override
    public TlsKeyExchangeType type() {
        return type;
    }
}
