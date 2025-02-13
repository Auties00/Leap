package it.auties.leap.tls.cipher.exchange.factory;

import it.auties.leap.tls.TlsContext;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchange;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchangeFactory;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchangeType;
import it.auties.leap.tls.cipher.exchange.client.ECDHClientKeyExchange;
import it.auties.leap.tls.cipher.exchange.server.ECDHServerKeyExchange;
import it.auties.leap.tls.exception.TlsException;

import java.nio.ByteBuffer;

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
    public TlsKeyExchange newRemoteKeyExchange(TlsContext context) {
        return switch (context.selectedMode().orElseThrow(() -> new TlsException("No mode was selected"))) {
            case SERVER -> newClientKeyExchange(context);
            case CLIENT -> newServerKeyExchange(context);
        };
    }

    @Override
    public TlsKeyExchange decodeLocalKeyExchange(TlsContext context, ByteBuffer buffer) {
        return switch (context.selectedMode().orElseThrow(() -> new TlsException("No mode was selected"))) {
            case CLIENT -> new ECDHClientKeyExchange(type, buffer);
            case SERVER -> new ECDHServerKeyExchange(type, buffer, context.supportedGroups());
        };
    }

    @Override
    public TlsKeyExchange decodeRemoteKeyExchange(TlsContext context, ByteBuffer buffer) {
        return switch (context.selectedMode().orElseThrow(() -> new TlsException("No mode was selected"))) {
            case SERVER -> new ECDHClientKeyExchange(type, buffer);
            case CLIENT -> new ECDHServerKeyExchange(type, buffer, context.supportedGroups());
        };
    }

    private ECDHClientKeyExchange newClientKeyExchange(TlsContext context) {
        var keyPair = context.remoteKeyExchange()
                .map(entry -> entry instanceof ECDHServerKeyExchange serverKeyExchange ? serverKeyExchange : null)
                .orElseThrow(() -> new TlsException("Missing remote ECDH key exchange for ephemeral key exchange"))
                .parameters()
                .toGroup(context)
                .generateLocalKeyPair(context);
        context.setLocalKeyPair(keyPair);
        return new ECDHClientKeyExchange(type, keyPair.getPublic().getEncoded());
    }

    private ECDHServerKeyExchange newServerKeyExchange(TlsContext context) {
        for(var group : context.supportedGroups()) {
            var parameters = group.toEllipticCurveParameters();
            if(parameters.isPresent()) {
                var keyPair = group.generateLocalKeyPair(context);
                context.setLocalKeyPair(keyPair);
                return new ECDHServerKeyExchange(type, parameters.get(), keyPair.getPublic().getEncoded());
            }
        }
        throw new TlsException("No supported group provides ec support: " + context.supportedGroups());
    }

    @Override
    public TlsKeyExchangeType type() {
        return type;
    }
}
