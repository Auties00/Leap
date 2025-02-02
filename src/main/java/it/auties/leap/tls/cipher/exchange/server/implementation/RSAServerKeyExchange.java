package it.auties.leap.tls.cipher.exchange.server.implementation;

import it.auties.leap.tls.cipher.exchange.TlsKeyExchange;
import it.auties.leap.tls.cipher.exchange.client.TlsClientKeyExchange;
import it.auties.leap.tls.cipher.exchange.server.TlsServerKeyExchange;
import it.auties.leap.tls.cipher.exchange.server.TlsServerKeyExchangeFactory;

import java.nio.ByteBuffer;
import java.security.PrivateKey;
import java.security.PublicKey;

import static it.auties.leap.tls.util.BufferUtils.*;

public final class RSAServerKeyExchange implements TlsServerKeyExchange {
    private static final TlsServerKeyExchangeFactory FACTORY = engine -> {
        return new RSAServerKeyExchange(new byte[0], new byte[0]);
    };

    private final byte[] modulus;
    private final byte[] exponent;

    public RSAServerKeyExchange(byte[] modulus, byte[] exponent) {
        this.modulus = modulus;
        this.exponent = exponent;
    }

    public RSAServerKeyExchange(ByteBuffer buffer) {
        this.modulus = readBytesLittleEndian16(buffer);
        this.exponent = readBytesLittleEndian16(buffer);
    }

    public static TlsServerKeyExchangeFactory factory() {
        return FACTORY;
    }

    @Override
    public void serialize(ByteBuffer buffer) {
        writeBytesLittleEndian16(buffer, modulus);
        writeBytesLittleEndian16(buffer, exponent);
    }

    @Override
    public int length() {
        return INT16_LENGTH + modulus.length
                + INT16_LENGTH + exponent.length;
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
