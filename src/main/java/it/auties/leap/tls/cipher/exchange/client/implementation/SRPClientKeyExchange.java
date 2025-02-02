package it.auties.leap.tls.cipher.exchange.client.implementation;

import it.auties.leap.tls.cipher.exchange.TlsKeyExchange;
import it.auties.leap.tls.cipher.exchange.client.TlsClientKeyExchange;
import it.auties.leap.tls.cipher.exchange.client.TlsClientKeyExchangeFactory;
import it.auties.leap.tls.cipher.exchange.server.TlsServerKeyExchange;

import java.nio.ByteBuffer;
import java.security.PrivateKey;
import java.security.PublicKey;

import static it.auties.leap.tls.util.BufferUtils.*;

public final class SRPClientKeyExchange implements TlsClientKeyExchange {
    private static final TlsClientKeyExchangeFactory FACTORY = engine -> {
        return new SRPClientKeyExchange(new byte[0]);
    };

    private final byte[] srpA;

    public SRPClientKeyExchange(byte[] srpA) {
        this.srpA = srpA;
    }

    public SRPClientKeyExchange(ByteBuffer buffer) {
        this.srpA = readBytesLittleEndian16(buffer);
    }

    public static TlsClientKeyExchangeFactory factory() {
        return FACTORY;
    }

    @Override
    public void serialize(ByteBuffer buffer) {
        writeBytesLittleEndian16(buffer, srpA);
    }

    @Override
    public int length() {
        return INT16_LENGTH + srpA.length;
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
