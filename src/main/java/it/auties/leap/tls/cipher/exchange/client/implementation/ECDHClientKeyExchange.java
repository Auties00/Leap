package it.auties.leap.tls.cipher.exchange.client.implementation;

import it.auties.leap.tls.cipher.exchange.client.TlsClientKeyExchange;
import it.auties.leap.tls.cipher.exchange.client.TlsClientKeyExchangeFactory;
import it.auties.leap.tls.exception.TlsException;

import java.nio.ByteBuffer;
import java.security.PrivateKey;

import static it.auties.leap.tls.util.BufferUtils.*;

//  For ECC cipher suites, this indicates whether
//      the client's ECDH public key is in the client's certificate
//      ("implicit") or is provided, as an ephemeral ECDH public key, in
//      the ClientKeyExchange message ("explicit").  (This is "explicit"
//      in ECC cipher suites except when the client uses the
//      ECDSA_fixed_ECDH or RSA_fixed_ECDH client authentication
//      mechanism.)
public final class ECDHClientKeyExchange implements TlsClientKeyExchange {
    private static final TlsClientKeyExchangeFactory FACTORY = engine -> {
        var publicKey = engine.localKeyPair()
                .map(keyPair -> keyPair.getPublic().getEncoded())
                .orElseThrow(() -> new TlsException("Missing key pair"));
        return new ECDHClientKeyExchange(publicKey);
    };

    private final byte[] publicKey;

    public ECDHClientKeyExchange(byte[] publicKey) {
        this.publicKey = publicKey;
    }

    public ECDHClientKeyExchange(ByteBuffer buffer) {
        this.publicKey = readBytesLittleEndian8(buffer);
    }

    public static TlsClientKeyExchangeFactory factory() {
        return FACTORY;
    }

    @Override
    public void serialize(ByteBuffer buffer) {
        writeBytesLittleEndian8(buffer, publicKey);
    }

    @Override
    public int length() {
        return INT8_LENGTH + publicKey.length;
    }

    @Override
    public byte[] generatePreMasterSecret(PrivateKey privateKey, ByteBuffer source) {
        throw new UnsupportedOperationException();
    }
}
