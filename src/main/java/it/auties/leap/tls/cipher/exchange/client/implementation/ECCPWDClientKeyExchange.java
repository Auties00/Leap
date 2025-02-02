package it.auties.leap.tls.cipher.exchange.client.implementation;

import it.auties.leap.tls.cipher.exchange.TlsKeyExchange;
import it.auties.leap.tls.cipher.exchange.client.TlsClientKeyExchange;
import it.auties.leap.tls.cipher.exchange.client.TlsClientKeyExchangeFactory;
import it.auties.leap.tls.cipher.exchange.server.TlsServerKeyExchange;
import it.auties.leap.tls.exception.TlsException;

import java.nio.ByteBuffer;
import java.security.PrivateKey;
import java.security.PublicKey;

import static it.auties.leap.tls.util.BufferUtils.*;

public final class ECCPWDClientKeyExchange implements TlsClientKeyExchange {
    private static final TlsClientKeyExchangeFactory FACTORY = engine -> {
        var publicKey = engine.localKeyPair()
                .map(keyPair -> keyPair.getPublic().getEncoded())
                .orElseThrow(() -> new TlsException("Missing key pair"));
        return new ECCPWDClientKeyExchange(publicKey, new byte[0]);
    };

    private final byte[] publicKey;
    private final byte[] password;

    public ECCPWDClientKeyExchange(byte[] publicKey, byte[] password) {
        this.password = password;
        this.publicKey = publicKey;
    }

    public ECCPWDClientKeyExchange(ByteBuffer buffer) {
        this.publicKey = readBytesLittleEndian8(buffer);
        this.password = readBytesLittleEndian8(buffer);
    }

    public static TlsClientKeyExchangeFactory factory() {
        return FACTORY;
    }

    @Override
    public void serialize(ByteBuffer buffer) {
        writeBytesLittleEndian8(buffer, publicKey);
        writeBytesLittleEndian8(buffer, password);
    }

    @Override
    public int length() {
        return INT8_LENGTH + publicKey.length +
                INT8_LENGTH + password.length;
    }

    @Override
    public TlsClientKeyExchange decodeLocal(ByteBuffer buffer) {
        return null;
    }

    @Override
    public TlsServerKeyExchange decodeRemote(ByteBuffer buffer) {
        return null;
    }

    @Override
    public byte[] generatePreMasterSecret(PrivateKey localPrivateKey, PublicKey remoteCertificatePublicKey, TlsKeyExchange remoteKeyExchange) {
        throw new UnsupportedOperationException();
    }
}
