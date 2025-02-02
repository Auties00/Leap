package it.auties.leap.tls.cipher.exchange.client.implementation;

import it.auties.leap.tls.cipher.exchange.TlsKeyExchange;
import it.auties.leap.tls.cipher.exchange.client.TlsClientKeyExchange;
import it.auties.leap.tls.cipher.exchange.client.TlsClientKeyExchangeFactory;
import it.auties.leap.tls.cipher.exchange.server.TlsServerKeyExchange;
import it.auties.leap.tls.exception.TlsException;

import java.nio.ByteBuffer;
import java.security.PrivateKey;
import java.security.PublicKey;

public final class NoneClientKeyExchange implements TlsClientKeyExchange {
    private static final NoneClientKeyExchange INSTANCE = new NoneClientKeyExchange();
    private static final TlsClientKeyExchangeFactory FACTORY = _ -> INSTANCE;

    private NoneClientKeyExchange() {

    }

    public NoneClientKeyExchange(ByteBuffer buffer) {
        if (buffer.hasRemaining()) {
            throw new TlsException("Expected empty payload");
        }
    }

    public static NoneClientKeyExchange instance() {
        return INSTANCE;
    }

    public static TlsClientKeyExchangeFactory factory() {
        return FACTORY;
    }

    @Override
    public void serialize(ByteBuffer buffer) {

    }

    @Override
    public int length() {
        return 0;
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
