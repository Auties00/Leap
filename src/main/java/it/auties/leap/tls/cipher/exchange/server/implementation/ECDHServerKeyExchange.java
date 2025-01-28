package it.auties.leap.tls.cipher.exchange.server.implementation;

import it.auties.leap.tls.cipher.exchange.server.TlsServerKeyExchange;
import it.auties.leap.tls.cipher.exchange.server.TlsServerKeyExchangeFactory;
import it.auties.leap.tls.ec.TlsECParameters;
import it.auties.leap.tls.ec.TlsECParametersDecoder;
import it.auties.leap.tls.exception.TlsException;

import java.nio.ByteBuffer;
import java.security.PrivateKey;

import static it.auties.leap.tls.util.BufferUtils.*;

public final class ECDHServerKeyExchange implements TlsServerKeyExchange {
    private static final TlsServerKeyExchangeFactory FACTORY = engine -> {
        var publicKey = engine.localKeyPair()
                .map(keyPair -> keyPair.getPublic().getEncoded())
                .orElseThrow(() -> new TlsException("Missing key pair"));
        return new ECDHServerKeyExchange(null, publicKey);
    };

    private final TlsECParameters params;
    private final byte[] publicKey;

    public ECDHServerKeyExchange(TlsECParameters params, byte[] publicKey) {
        this.params = params;
        this.publicKey = publicKey;
    }

    public ECDHServerKeyExchange(ByteBuffer buffer, TlsECParametersDecoder decoder) {
        this.params = decoder.decodeParameters(buffer);
        this.publicKey = readBytesLittleEndian8(buffer);
    }

    public static TlsServerKeyExchangeFactory factory() {
        return FACTORY;
    }

    @Override
    public void serialize(ByteBuffer buffer) {
        writeBytesLittleEndian8(buffer, publicKey);
    }

    @Override
    public int length() {
        return params.length()
                + INT8_LENGTH + publicKey.length;
    }

    @Override
    public byte[] generatePreMasterSecret(PrivateKey privateKey, ByteBuffer source) {
        throw new UnsupportedOperationException();
    }
}
