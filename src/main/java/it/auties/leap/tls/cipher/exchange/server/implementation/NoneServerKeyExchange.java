package it.auties.leap.tls.cipher.exchange.server.implementation;

import it.auties.leap.tls.cipher.exchange.TlsKeyExchange;
import it.auties.leap.tls.cipher.exchange.client.TlsClientKeyExchange;
import it.auties.leap.tls.cipher.exchange.server.TlsServerKeyExchange;
import it.auties.leap.tls.cipher.exchange.server.TlsServerKeyExchangeFactory;
import it.auties.leap.tls.exception.TlsException;

import java.nio.ByteBuffer;
import java.security.PrivateKey;
import java.security.PublicKey;

public final class NoneServerKeyExchange implements TlsServerKeyExchange {
    private static final NoneServerKeyExchange INSTANCE = new NoneServerKeyExchange();
    private static final TlsServerKeyExchangeFactory FACTORY = _ -> INSTANCE;

    private NoneServerKeyExchange() {

    }

    public static NoneServerKeyExchange instance() {
        return INSTANCE;
    }

    public NoneServerKeyExchange(ByteBuffer buffer) {
        if (buffer.hasRemaining()) {
            throw new TlsException("Expected empty payload");
        }
    }

    public static TlsServerKeyExchangeFactory factory() {
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
    public TlsServerKeyExchange decodeLocal(ByteBuffer buffer) {
        throw new UnsupportedOperationException();
    }

    @Override
    public TlsClientKeyExchange decodeRemote(ByteBuffer buffer) {
        throw new UnsupportedOperationException();
    }

    @Override
    public byte[] generatePreMasterSecret(PrivateKey localPrivateKey, PublicKey remoteCertificatePublicKey, TlsKeyExchange remoteKeyExchange) {
        throw new UnsupportedOperationException();
    }
}
