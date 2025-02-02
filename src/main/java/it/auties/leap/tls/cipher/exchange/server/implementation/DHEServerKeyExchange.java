package it.auties.leap.tls.cipher.exchange.server.implementation;

import it.auties.leap.tls.cipher.exchange.TlsKeyExchange;
import it.auties.leap.tls.cipher.exchange.client.TlsClientKeyExchange;
import it.auties.leap.tls.cipher.exchange.client.implementation.DHClientKeyExchange;
import it.auties.leap.tls.cipher.exchange.client.implementation.DHEClientKeyExchange;
import it.auties.leap.tls.cipher.exchange.server.TlsServerKeyExchange;
import it.auties.leap.tls.cipher.exchange.server.TlsServerKeyExchangeFactory;
import it.auties.leap.tls.exception.TlsException;
import it.auties.leap.tls.util.KeyUtils;

import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;

import static it.auties.leap.tls.util.BufferUtils.*;

public final class DHEServerKeyExchange implements TlsServerKeyExchange {
    private static final TlsServerKeyExchangeFactory FACTORY = engine -> engine.localKeyPair()
            .map(keyPair -> new DHEServerKeyExchange(keyPair.getPublic()))
            .orElseThrow(() -> new TlsException("Missing keypair"));

    private final DHPublicKey publicKey;
    private final byte[] p;
    private final byte[] g;
    private final byte[] y;

    public DHEServerKeyExchange(PublicKey publicKey) {
        if(!(publicKey instanceof DHPublicKey dhPublicKey)) {
            throw new TlsException("Invalid DH public key");
        }

        this.publicKey = dhPublicKey;
        this.p = KeyUtils.toUnsignedLittleEndianBytes(dhPublicKey.getParams().getP());
        this.g = KeyUtils.toUnsignedLittleEndianBytes(dhPublicKey.getParams().getG());
        this.y = KeyUtils.toUnsignedLittleEndianBytes(dhPublicKey.getY());
    }

    public DHEServerKeyExchange(ByteBuffer buffer) {
        this.p = readBytesLittleEndian16(buffer);
        this.g = readBytesLittleEndian16(buffer);
        this.y = readBytesLittleEndian16(buffer);
        this.publicKey = KeyUtils.read(y, KeyUtils.fromUnsignedLittleEndianBytes(p), KeyUtils.fromUnsignedLittleEndianBytes(g));
    }

    public static TlsServerKeyExchangeFactory factory() {
        return FACTORY;
    }

    @Override
    public void serialize(ByteBuffer buffer) {
        writeBytesLittleEndian16(buffer, p);
        writeBytesLittleEndian16(buffer, g);
        writeBytesLittleEndian16(buffer, y);
    }

    @Override
    public int length() {
        return INT16_LENGTH + p.length
                + INT16_LENGTH + g.length
                + INT16_LENGTH + y.length;
    }

    @Override
    public TlsServerKeyExchange decodeLocal(ByteBuffer buffer) {
        return new DHEServerKeyExchange(buffer);
    }

    @Override
    public TlsClientKeyExchange decodeRemote(ByteBuffer buffer) {
        return new DHEClientKeyExchange(buffer, p, g);
    }

    @Override
    public byte[] generatePreMasterSecret(PrivateKey localPrivateKey, PublicKey remoteCertificatePublicKey, TlsKeyExchange remoteKeyExchange) {
        if(!(remoteKeyExchange instanceof DHClientKeyExchange clientKeyExchange)) {
            throw new TlsException("Remote key exchange mismatch: expected DHE");
        }
        try {
            var keyAgreement = KeyAgreement.getInstance("DH");
            keyAgreement.init(localPrivateKey);
            keyAgreement.doPhase(clientKeyExchange.publicKey(), true);
            return keyAgreement.generateSecret();
        } catch (GeneralSecurityException exception) {
            throw new TlsException("Cannot generate pre master secret", exception);
        }
    }

    public DHPublicKey publicKey() {
        return publicKey;
    }
}
