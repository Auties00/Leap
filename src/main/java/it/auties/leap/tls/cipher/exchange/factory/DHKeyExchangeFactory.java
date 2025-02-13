package it.auties.leap.tls.cipher.exchange.factory;

import it.auties.leap.tls.TlsContext;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchange;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchangeFactory;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchangeType;
import it.auties.leap.tls.cipher.exchange.client.DHClientKeyExchange;
import it.auties.leap.tls.cipher.exchange.server.DHServerKeyExchange;
import it.auties.leap.tls.exception.TlsException;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.KeyPairGenerator;

public class DHKeyExchangeFactory implements TlsKeyExchangeFactory {
    private static final DHKeyExchangeFactory STATIC = new DHKeyExchangeFactory(TlsKeyExchangeType.STATIC);
    private static final DHKeyExchangeFactory EPHEMERAL = new DHKeyExchangeFactory(TlsKeyExchangeType.EPHEMERAL);

    private final TlsKeyExchangeType type;
    private DHKeyExchangeFactory(TlsKeyExchangeType type) {
        this.type = type;
    }

    public static DHKeyExchangeFactory staticFactory() {
        return STATIC;
    }

    public static DHKeyExchangeFactory ephemeralFactory() {
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
            case CLIENT -> new DHClientKeyExchange(type, buffer);
            case SERVER -> new DHServerKeyExchange(type, buffer);
        };
    }

    @Override
    public TlsKeyExchange decodeRemoteKeyExchange(TlsContext context, ByteBuffer buffer) {
        return switch (context.selectedMode().orElseThrow(() -> new TlsException("No mode was selected"))) {
            case SERVER -> new DHClientKeyExchange(type, buffer);
            case CLIENT -> new DHServerKeyExchange(type, buffer);
        };
    }

    private TlsKeyExchange newClientKeyExchange(TlsContext context) {
        var remotePublicKey = switch (type) {
            case STATIC -> context.remotePublicKey()
                    .orElseThrow(() -> new TlsException("Missing remote public key for static key exchange"));
            case EPHEMERAL -> context.supportedGroups()
                    .getFirst()
                    .parseRemotePublicKey(context);
        };
        try {
            var kpg = KeyPairGenerator.getInstance(remotePublicKey.getAlgorithm());
            kpg.initialize(remotePublicKey.getParams());
            var keyPair = kpg.generateKeyPair();
            context.setLocalKeyPair(keyPair);
            return new DHClientKeyExchange(type, keyPair.getPublic());
        }catch (GeneralSecurityException exception) {
            throw new TlsException("Cannot generate client DH key pair", exception);
        }
    }

    private DHServerKeyExchange newServerKeyExchange(TlsContext context) {
        return context.localKeyPair()
                .map(keyPair -> new DHServerKeyExchange(type, keyPair.getPublic()))
                .orElseThrow(() -> new TlsException("Missing keypair"));
    }

    @Override
    public TlsKeyExchangeType type() {
        return type;
    }
}
