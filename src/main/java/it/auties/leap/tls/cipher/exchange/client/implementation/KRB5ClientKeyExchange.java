package it.auties.leap.tls.cipher.exchange.client.implementation;

import it.auties.leap.tls.cipher.exchange.TlsKeyExchange;
import it.auties.leap.tls.cipher.exchange.client.TlsClientKeyExchange;
import it.auties.leap.tls.cipher.exchange.client.TlsClientKeyExchangeFactory;
import it.auties.leap.tls.cipher.exchange.server.TlsServerKeyExchange;

import java.nio.ByteBuffer;
import java.security.PrivateKey;
import java.security.PublicKey;

import static it.auties.leap.tls.util.BufferUtils.*;

public final class KRB5ClientKeyExchange implements TlsClientKeyExchange {
    private static final TlsClientKeyExchangeFactory FACTORY = engine -> {
        return new KRB5ClientKeyExchange(new byte[0], new byte[0], new byte[0]);
    };

    private final byte[] ticket;
    private final byte[] authenticator;
    private final byte[] encryptedPreMasterSecret;

    public KRB5ClientKeyExchange(byte[] ticket, byte[] authenticator, byte[] encryptedPreMasterSecret) {
        this.ticket = ticket;
        this.authenticator = authenticator;
        this.encryptedPreMasterSecret = encryptedPreMasterSecret;
    }

    public KRB5ClientKeyExchange(ByteBuffer buffer) {
        this.ticket = readBytesLittleEndian16(buffer);
        this.authenticator = readBytesLittleEndian16(buffer);
        this.encryptedPreMasterSecret = readBytesLittleEndian16(buffer);
    }

    public static TlsClientKeyExchangeFactory factory() {
        return FACTORY;
    }

    @Override
    public void serialize(ByteBuffer buffer) {
        writeBytesLittleEndian16(buffer, ticket);
        writeBytesLittleEndian16(buffer, authenticator);
        writeBytesLittleEndian16(buffer, encryptedPreMasterSecret);
    }

    @Override
    public int length() {
        return INT16_LENGTH + ticket.length
                + INT16_LENGTH + authenticator.length
                + INT16_LENGTH + encryptedPreMasterSecret.length;
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
