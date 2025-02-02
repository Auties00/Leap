package it.auties.leap.tls.cipher.exchange.server.implementation;

import it.auties.leap.tls.cipher.exchange.client.TlsClientKeyExchange;
import it.auties.leap.tls.cipher.exchange.client.implementation.ECDHEClientKeyExchange;
import it.auties.leap.tls.cipher.exchange.server.TlsServerKeyExchange;
import it.auties.leap.tls.cipher.exchange.server.TlsServerKeyExchangeFactory;
import it.auties.leap.tls.ec.TlsECParameters;
import it.auties.leap.tls.ec.TlsECParametersDecoder;
import it.auties.leap.tls.exception.TlsException;

import java.nio.ByteBuffer;
import java.util.List;

public final class ECDHEServerKeyExchange extends ECDHServerKeyExchange {
    private static final TlsServerKeyExchangeFactory FACTORY = engine -> {
        var publicKey = engine.localKeyPair()
                .map(keyPair -> keyPair.getPublic().getEncoded())
                .orElseThrow(() -> new TlsException("Missing key pair"));
        return new ECDHEServerKeyExchange(null, publicKey);
    };

    public ECDHEServerKeyExchange(TlsECParameters params, byte[] publicKey) {
        super(params, publicKey);
    }

    public ECDHEServerKeyExchange(ByteBuffer buffer, TlsECParametersDecoder decoder) {
        super(buffer, decoder);
    }

    public ECDHEServerKeyExchange(ByteBuffer buffer, List<TlsECParametersDecoder> decoders) {
        super(buffer, decoders);
    }

    public static TlsServerKeyExchangeFactory factory() {
        return FACTORY;
    }

    @Override
    public TlsServerKeyExchange decodeLocal(ByteBuffer buffer) {
        return new ECDHEServerKeyExchange(buffer, params.decoder());
    }

    @Override
    public TlsClientKeyExchange decodeRemote(ByteBuffer buffer) {
        return new ECDHEClientKeyExchange(buffer, List.of(params.decoder()));
    }
}
