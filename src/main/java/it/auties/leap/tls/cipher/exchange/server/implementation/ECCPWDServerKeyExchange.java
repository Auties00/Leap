package it.auties.leap.tls.cipher.exchange.server.implementation;

import it.auties.leap.tls.cipher.exchange.server.TlsServerKeyExchange;
import it.auties.leap.tls.cipher.exchange.server.TlsServerKeyExchangeFactory;
import it.auties.leap.tls.ec.TlsECParameters;
import it.auties.leap.tls.ec.TlsECParametersDecoder;
import it.auties.leap.tls.exception.TlsException;

import java.nio.ByteBuffer;
import java.security.PrivateKey;

import static it.auties.leap.tls.util.BufferUtils.*;

public final class ECCPWDServerKeyExchange implements TlsServerKeyExchange {
    private static final TlsServerKeyExchangeFactory FACTORY = engine -> {
        var publicKey = engine.localKeyPair()
                .map(keyPair -> keyPair.getPublic().getEncoded())
                .orElseThrow(() -> new TlsException("Missing key pair"));
        return new ECCPWDServerKeyExchange(new byte[0], null, publicKey, new byte[0]);
    };

    private final byte[] salt;
    private final TlsECParameters params;
    private final byte[] publicKey;
    private final byte[] password;

    public ECCPWDServerKeyExchange(byte[] salt, TlsECParameters params, byte[] publicKey, byte[] password) {
        this.salt = salt;
        this.params = params;
        this.publicKey = publicKey;
        this.password = password;
    }

    public ECCPWDServerKeyExchange(ByteBuffer buffer, TlsECParametersDecoder decoder) {
        this.salt = readBytesLittleEndian8(buffer);
        this.params = decoder.decodeParameters(buffer);
        this.publicKey = readBytesLittleEndian8(buffer);
        this.password = readBytesLittleEndian8(buffer);
    }

    public static TlsServerKeyExchangeFactory factory() {
        return FACTORY;
    }

    @Override
    public void serialize(ByteBuffer buffer) {
        writeBytesLittleEndian16(buffer, salt);
        params.serialize(buffer);
        writeBytesLittleEndian8(buffer, publicKey);
        writeBytesLittleEndian8(buffer, password);
    }

    @Override
    public int length() {
        return INT8_LENGTH + salt.length
                + params.length()
                + INT8_LENGTH + publicKey.length
                + INT8_LENGTH + password.length;
    }

    @Override
    public byte[] generatePreMasterSecret(PrivateKey privateKey, ByteBuffer source) {
        throw new UnsupportedOperationException();
    }
}
