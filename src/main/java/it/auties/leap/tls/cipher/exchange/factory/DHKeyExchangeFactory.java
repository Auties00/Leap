package it.auties.leap.tls.cipher.exchange.factory;

import it.auties.leap.tls.TlsContext;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchange;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchangeFactory;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchangeType;
import it.auties.leap.tls.cipher.exchange.client.DHClientKeyExchange;
import it.auties.leap.tls.cipher.exchange.server.DHServerKeyExchange;
import it.auties.leap.tls.exception.TlsException;
import it.auties.leap.tls.util.KeyUtils;

import javax.crypto.interfaces.DHPublicKey;
import java.nio.ByteBuffer;
import java.util.NoSuchElementException;

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
    public TlsKeyExchange decodeRemoteKeyExchange(TlsContext context, ByteBuffer buffer) {
        return switch (context.selectedMode().orElseThrow(() -> new TlsException("No mode was selected"))) {
            case SERVER -> new DHClientKeyExchange(type, buffer);
            case CLIENT -> new DHServerKeyExchange(type, buffer);
        };
    }

    // TODO: HERE
    private DHClientKeyExchange newClientKeyExchange(TlsContext context) {
        var group = context.localPreferredFiniteField()
                .orElseThrow(() -> new NoSuchElementException("No supported group is a finite field"));
        var keyPair = group.generateLocalKeyPair(context);
        context.setLocalKeyPair(keyPair);
        var publicKey = (DHPublicKey) keyPair.getPublic();
        var y = KeyUtils.toUnsignedLittleEndianBytes(publicKey.getY());
        return new DHClientKeyExchange(type, y);
    }

    private DHServerKeyExchange newServerKeyExchange(TlsContext context) {
        var group = context.localPreferredFiniteField()
                .orElseThrow(() -> new NoSuchElementException("No supported group is a finite field"));
        var keyPair = group.generateLocalKeyPair(context);
        context.setLocalKeyPair(keyPair);
        var publicKey = (DHPublicKey) keyPair.getPublic();
        var p = publicKey.getParams().getP().toByteArray();
        var g = publicKey.getParams().getG().toByteArray();
        var y = KeyUtils.toUnsignedLittleEndianBytes(publicKey.getY());
        return new DHServerKeyExchange(type, p, g, y);
    }


    @Override
    public TlsKeyExchangeType type() {
        return type;
    }
}
