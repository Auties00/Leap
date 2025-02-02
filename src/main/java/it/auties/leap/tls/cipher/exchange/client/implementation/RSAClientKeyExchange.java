package it.auties.leap.tls.cipher.exchange.client.implementation;

import it.auties.leap.tls.cipher.exchange.TlsKeyExchange;
import it.auties.leap.tls.cipher.exchange.client.TlsClientKeyExchange;
import it.auties.leap.tls.cipher.exchange.client.TlsClientKeyExchangeFactory;
import it.auties.leap.tls.cipher.exchange.server.TlsServerKeyExchange;

import java.nio.ByteBuffer;
import java.security.PrivateKey;
import java.security.PublicKey;

import static it.auties.leap.tls.util.BufferUtils.*;

public final class RSAClientKeyExchange implements TlsClientKeyExchange {
    private static final TlsClientKeyExchangeFactory FACTORY = engine -> {
        return new RSAClientKeyExchange(new byte[0]);
    };

    private final byte[] preMasterSecret;

    public RSAClientKeyExchange(byte[] preMasterSecret) {
        this.preMasterSecret = preMasterSecret;
    }

    public RSAClientKeyExchange(ByteBuffer buffer) {
        this.preMasterSecret = readBytesLittleEndian16(buffer);
    }

    public static TlsClientKeyExchangeFactory factory() {
        return FACTORY;
    }

    @Override
    public void serialize(ByteBuffer buffer) {
        writeBytesLittleEndian16(buffer, preMasterSecret);
    }

    @Override
    public int length() {
        return INT16_LENGTH + preMasterSecret.length;
    }

    @Override
    public TlsClientKeyExchange decodeLocal(ByteBuffer buffer) {
        throw new UnsupportedOperationException();
    }

    @Override
    public TlsServerKeyExchange decodeRemote(ByteBuffer buffer) {
        throw new UnsupportedOperationException();
    }

    @Override
    public byte[] generatePreMasterSecret(PrivateKey localPrivateKey, PublicKey remoteCertificatePublicKey, TlsKeyExchange remoteKeyExchange) {
        throw new UnsupportedOperationException();
    }
}
