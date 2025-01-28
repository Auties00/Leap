package it.auties.leap.tls.cipher.exchange.server.implementation;

import it.auties.leap.tls.cipher.exchange.server.TlsServerKeyExchange;
import it.auties.leap.tls.cipher.exchange.server.TlsServerKeyExchangeFactory;
import it.auties.leap.tls.exception.TlsException;

import java.nio.ByteBuffer;
import java.security.PrivateKey;

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
    public byte[] generatePreMasterSecret(PrivateKey privateKey, ByteBuffer source) {
        throw new UnsupportedOperationException();
    }
}
