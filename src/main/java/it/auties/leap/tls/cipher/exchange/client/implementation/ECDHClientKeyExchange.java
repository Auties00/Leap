package it.auties.leap.tls.cipher.exchange.client.implementation;

import it.auties.leap.tls.cipher.exchange.TlsKeyExchange;
import it.auties.leap.tls.cipher.exchange.client.TlsClientKeyExchange;
import it.auties.leap.tls.cipher.exchange.client.TlsClientKeyExchangeFactory;
import it.auties.leap.tls.cipher.exchange.server.TlsServerKeyExchange;
import it.auties.leap.tls.cipher.exchange.server.implementation.ECDHServerKeyExchange;
import it.auties.leap.tls.ec.TlsECParametersDecoder;
import it.auties.leap.tls.exception.TlsException;

import javax.crypto.KeyAgreement;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.List;

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
        return new ECDHClientKeyExchange(publicKey, engine.ecParametersDecoders());
    };

    private final byte[] publicKey;
    private final List<TlsECParametersDecoder> decoders;

    public ECDHClientKeyExchange(byte[] publicKey, List<TlsECParametersDecoder> decoders) {
        this.publicKey = publicKey;
        this.decoders = decoders;
    }

    public ECDHClientKeyExchange(ByteBuffer buffer, List<TlsECParametersDecoder> decoders) {
        this.publicKey = readBytesLittleEndian8(buffer);
        this.decoders = decoders;
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
    public TlsClientKeyExchange decodeLocal(ByteBuffer buffer) {
        return new ECDHClientKeyExchange(buffer, decoders);
    }

    @Override
    public TlsServerKeyExchange decodeRemote(ByteBuffer buffer) {
        return new ECDHServerKeyExchange(buffer, decoders);
    }

    @Override
    public byte[] generatePreMasterSecret(PrivateKey localPrivateKey, PublicKey remoteCertificatePublicKey, TlsKeyExchange remoteKeyExchange) {
        try {
            var keyAgreement = KeyAgreement.getInstance("ECDH");
            keyAgreement.init(localPrivateKey);
            keyAgreement.doPhase(null, true);
            return keyAgreement.generateSecret();
        } catch (GeneralSecurityException exception) {
            throw new TlsException("Cannot generate pre master secret", exception);
        }
    }
}
