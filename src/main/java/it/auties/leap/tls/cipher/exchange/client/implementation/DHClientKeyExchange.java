package it.auties.leap.tls.cipher.exchange.client.implementation;

import it.auties.leap.tls.cipher.exchange.TlsKeyExchange;
import it.auties.leap.tls.cipher.exchange.client.TlsClientKeyExchange;
import it.auties.leap.tls.cipher.exchange.client.TlsClientKeyExchangeFactory;
import it.auties.leap.tls.cipher.exchange.server.TlsServerKeyExchange;
import it.auties.leap.tls.cipher.exchange.server.implementation.DHServerKeyExchange;
import it.auties.leap.tls.exception.TlsException;
import it.auties.leap.tls.util.KeyUtils;

import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;

import static it.auties.leap.tls.util.BufferUtils.*;
import static it.auties.leap.tls.util.KeyUtils.fromUnsignedLittleEndianBytes;
import static it.auties.leap.tls.util.KeyUtils.toUnsignedLittleEndianBytes;

// This structure conveys the client's Diffie-Hellman public value
//       (Yc) if it was not already included in the client's certificate.
//       The encoding used for Yc is determined by the enumerated
//       PublicValueEncoding. This structure is a variant of the client
//       key exchange message, not a message in itself.
public final class DHClientKeyExchange implements TlsClientKeyExchange {
    private static final TlsClientKeyExchangeFactory FACTORY = engine -> engine.localKeyPair()
            .map(keyPair -> new DHClientKeyExchange(keyPair.getPublic()))
            .orElseThrow(() -> new TlsException("Missing keypair"));

    private final byte[] y;
    private final DHPublicKey publicKey;

    public DHClientKeyExchange(PublicKey publicKey) {
        if(!(publicKey instanceof DHPublicKey dhPublicKey)) {
            throw new TlsException("Invalid DH public key");
        }

        this.y = toUnsignedLittleEndianBytes(dhPublicKey.getY());
        this.publicKey = dhPublicKey;
    }

    public DHClientKeyExchange(ByteBuffer buffer, byte[] p, byte[] g) {
        this(buffer, KeyUtils.fromUnsignedLittleEndianBytes(p), fromUnsignedLittleEndianBytes(g));
    }

    public DHClientKeyExchange(ByteBuffer buffer, BigInteger p, BigInteger g) {
        this.y = readBytesLittleEndian8(buffer);
        this.publicKey = KeyUtils.read(y, p, g);
    }


    public static TlsClientKeyExchangeFactory factory() {
        return FACTORY;
    }

    @Override
    public void serialize(ByteBuffer buffer) {
        writeBytesLittleEndian8(buffer, y);
    }

    @Override
    public int length() {
        return INT8_LENGTH + y.length;
    }

    public DHPublicKey publicKey() {
        return publicKey;
    }

    @Override
    public TlsClientKeyExchange decodeLocal(ByteBuffer buffer) {
        return new DHClientKeyExchange(buffer, publicKey.getParams().getP(), publicKey.getParams().getG());
    }

    @Override
    public TlsServerKeyExchange decodeRemote(ByteBuffer buffer) {
        return new DHServerKeyExchange(buffer);
    }

    @Override
    public byte[] generatePreMasterSecret(PrivateKey localPrivateKey, PublicKey remoteCertificatePublicKey, TlsKeyExchange remoteKeyExchange) {
        if (!(remoteKeyExchange instanceof DHServerKeyExchange serverKeyExchange)) {
            throw new TlsException("Remote key exchange mismatch: expected DH");
        }

        try {
            var keyAgreement = KeyAgreement.getInstance("DH");
            keyAgreement.init(localPrivateKey);
            keyAgreement.doPhase(serverKeyExchange.publicKey(), true);
            return keyAgreement.generateSecret();
        } catch (GeneralSecurityException exception) {
            throw new TlsException("Cannot generate pre master secret", exception);
        }
    }
}
