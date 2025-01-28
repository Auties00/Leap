package it.auties.leap.tls.cipher.exchange.client.implementation;

import it.auties.leap.tls.cipher.exchange.client.TlsClientKeyExchange;
import it.auties.leap.tls.cipher.exchange.client.TlsClientKeyExchangeFactory;

import java.nio.ByteBuffer;
import java.security.PrivateKey;

import static it.auties.leap.tls.util.BufferUtils.writeBytes;

// https://www.ietf.org/archive/id/draft-smyshlyaev-tls12-gost-suites-18.html
public final class GOSTRClientKeyExchange implements TlsClientKeyExchange {
    private static final TlsClientKeyExchangeFactory FACTORY = engine -> {
        return new GOSTRClientKeyExchange(new byte[0]);
    };

    private final byte[] encodedKeyTransport;

    public GOSTRClientKeyExchange(byte[] encodedKeyTransport) {
        this.encodedKeyTransport = encodedKeyTransport;
    }

    public static TlsClientKeyExchangeFactory factory() {
        return FACTORY;
    }

    @Override
    public void serialize(ByteBuffer buffer) {
        writeBytes(buffer, encodedKeyTransport);
    }

    @Override
    public int length() {
        return encodedKeyTransport.length;
    }

    @Override
    public byte[] generatePreMasterSecret(PrivateKey privateKey, ByteBuffer source) {
        throw new UnsupportedOperationException();
    }
}
