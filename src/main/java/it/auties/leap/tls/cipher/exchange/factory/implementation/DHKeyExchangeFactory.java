package it.auties.leap.tls.cipher.exchange.factory.implementation;

import it.auties.leap.tls.cipher.exchange.TlsKeyExchange;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchangeType;
import it.auties.leap.tls.cipher.exchange.client.implementation.DHClientKeyExchange;
import it.auties.leap.tls.cipher.exchange.factory.TlsKeyExchangeFactory;
import it.auties.leap.tls.cipher.exchange.server.implementation.DHServerKeyExchange;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.exception.TlsException;
import it.auties.leap.tls.group.TlsSupportedFiniteField;

import javax.crypto.interfaces.DHPublicKey;
import java.nio.ByteBuffer;
import java.util.Arrays;
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

    private DHClientKeyExchange newClientKeyExchange(TlsContext context) {
        var remoteDhKeyExchange = context.remoteKeyExchange()
                .map(entry -> entry instanceof DHServerKeyExchange serverKeyExchange ? serverKeyExchange : null)
                .orElseThrow(() -> new TlsException("Missing remote DH key exchange"));
        for(var group : context.localSupportedGroups()) {
            if(group instanceof TlsSupportedFiniteField finiteField) {
                if(finiteField.accepts(remoteDhKeyExchange)) {
                    var keyPair = finiteField.generateLocalKeyPair(context);
                    context.setLocalKeyPair(keyPair);
                    var y = ((DHPublicKey) keyPair.getPublic()).getY()
                            .toByteArray();
                    System.out.println("Local public key: " + Arrays.toString(y));
                    return new DHClientKeyExchange(type, y);
                }
            }
        }
        throw new TlsException("Unsupported DH group");
    }

    private DHServerKeyExchange newServerKeyExchange(TlsContext context) {
        var group = context.localPreferredFiniteField()
                .orElseThrow(() -> new NoSuchElementException("No supported group is a finite field"));
        var keyPair = group.generateLocalKeyPair(context);
        context.setLocalKeyPair(keyPair);
        var publicKey = (DHPublicKey) keyPair.getPublic();
        var p = publicKey.getParams()
                .getP()
                .toByteArray();
        var g = publicKey.getParams()
                .getG()
                .toByteArray();
        var y = publicKey.getY()
                .toByteArray();
        return new DHServerKeyExchange(type, p, g, y);
    }

    @Override
    public TlsKeyExchangeType type() {
        return type;
    }

}
