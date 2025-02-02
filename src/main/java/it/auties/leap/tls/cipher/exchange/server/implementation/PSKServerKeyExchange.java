package it.auties.leap.tls.cipher.exchange.server.implementation;

import it.auties.leap.tls.cipher.exchange.TlsKeyExchange;
import it.auties.leap.tls.cipher.exchange.client.TlsClientKeyExchange;
import it.auties.leap.tls.cipher.exchange.server.TlsServerKeyExchange;
import it.auties.leap.tls.cipher.exchange.server.TlsServerKeyExchangeFactory;

import java.nio.ByteBuffer;
import java.security.PrivateKey;
import java.security.PublicKey;

import static it.auties.leap.tls.util.BufferUtils.*;

public final class PSKServerKeyExchange implements TlsServerKeyExchange {
    private static final TlsServerKeyExchangeFactory FACTORY = engine -> {
        return new PSKServerKeyExchange(new byte[0]);
    };

    private final byte[] identityKeyHint;

    public PSKServerKeyExchange(byte[] identityKeyHint) {
        this.identityKeyHint = identityKeyHint;
    }

    public PSKServerKeyExchange(ByteBuffer buffer) {
        this(readBytesLittleEndian16(buffer));
    }

    public static TlsServerKeyExchangeFactory factory() {
        return FACTORY;
    }

    @Override
    public void serialize(ByteBuffer buffer) {
        writeBytesLittleEndian16(buffer, identityKeyHint);
    }

    @Override
    public int length() {
        return INT16_LENGTH + identityKeyHint.length;
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
