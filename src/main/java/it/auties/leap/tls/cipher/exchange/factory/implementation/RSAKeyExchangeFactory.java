package it.auties.leap.tls.cipher.exchange.factory.implementation;

import it.auties.leap.tls.cipher.exchange.TlsKeyExchange;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchangeType;
import it.auties.leap.tls.cipher.exchange.client.implementation.RSAClientKeyExchange;
import it.auties.leap.tls.cipher.exchange.factory.TlsKeyExchangeFactory;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.exception.TlsException;
import it.auties.leap.tls.secret.TlsPreMasterSecretGenerator;

import java.nio.ByteBuffer;

public class RSAKeyExchangeFactory implements TlsKeyExchangeFactory {
    private static final RSAKeyExchangeFactory STATIC_FACTORY = new RSAKeyExchangeFactory();

    private RSAKeyExchangeFactory() {

    }

    public static RSAKeyExchangeFactory staticFactory() {
        return STATIC_FACTORY;
    }

    @Override
    public TlsKeyExchange newLocalKeyExchange(TlsContext context) {
        return switch (context.selectedMode().orElseThrow(() -> new TlsException("No mode was selected"))) {
            case CLIENT -> newClientKeyExchange(context);
            case SERVER -> throw new TlsException("Unsupported RSA key exchange");
        };
    }

    private RSAClientKeyExchange newClientKeyExchange(TlsContext context) {
        var preMasterSecret = TlsPreMasterSecretGenerator.rsa()
                .generatePreMasterSecret(context);
        return new RSAClientKeyExchange(preMasterSecret);
    }

    @Override
    public TlsKeyExchange decodeRemoteKeyExchange(TlsContext context, ByteBuffer buffer) {
        return switch (context.selectedMode().orElseThrow(() -> new TlsException("No mode was selected"))) {
            case SERVER -> new RSAClientKeyExchange(buffer);
            case CLIENT -> throw new TlsException("Unsupported RSA key exchange");
        };
    }

    @Override
    public TlsKeyExchangeType type() {
        return TlsKeyExchangeType.STATIC;
    }

}
