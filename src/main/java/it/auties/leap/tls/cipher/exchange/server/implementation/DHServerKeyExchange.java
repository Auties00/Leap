package it.auties.leap.tls.cipher.exchange.server.implementation;

import it.auties.leap.tls.cipher.exchange.client.implementation.DHClientKeyExchange;
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
import static it.auties.leap.tls.util.KeyUtils.toUnsignedLittleEndianBytes;

public final class DHServerKeyExchange implements TlsServerKeyExchange {
    private static final TlsServerKeyExchangeFactory FACTORY = engine -> engine.localKeyPair()
            .map(keyPair -> new DHServerKeyExchange(keyPair.getPublic()))
            .orElseThrow(() -> new TlsException("Missing keypair"));

    private final DHPublicKey publicKey;
    private final byte[] p;
    private final byte[] g;
    private final byte[] y;

    public DHServerKeyExchange(PublicKey publicKey) {
        if(!(publicKey instanceof DHPublicKey dhPublicKey)) {
            throw new TlsException("Invalid DH public key");
        }

        this.publicKey = dhPublicKey;
        this.p = toUnsignedLittleEndianBytes(dhPublicKey.getParams().getP());
        this.g = toUnsignedLittleEndianBytes(dhPublicKey.getParams().getG());
        this.y = toUnsignedLittleEndianBytes(dhPublicKey.getY());
    }

    public DHServerKeyExchange(ByteBuffer buffer) {
        this.p = readBytesLittleEndian16(buffer);
        this.g = readBytesLittleEndian16(buffer);
        this.y = readBytesLittleEndian16(buffer);
        this.publicKey = KeyUtils.read(y, p, g);
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
    public byte[] generatePreMasterSecret(PrivateKey privateKey, ByteBuffer source) {
        try {
            var clientKeyExchange = new DHClientKeyExchange(source, p, g);
            var keyAgreement = KeyAgreement.getInstance("DH");
            keyAgreement.init(privateKey);
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
