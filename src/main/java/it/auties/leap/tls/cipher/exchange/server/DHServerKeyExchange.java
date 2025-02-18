package it.auties.leap.tls.cipher.exchange.server;

import it.auties.leap.tls.cipher.exchange.TlsKeyExchangeType;
import it.auties.leap.tls.cipher.exchange.TlsServerKeyExchange;
import it.auties.leap.tls.exception.TlsException;
import it.auties.leap.tls.key.TlsPreMasterSecretGenerator;
import it.auties.leap.tls.util.KeyUtils;

import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;

import static it.auties.leap.tls.util.BufferUtils.*;

public final class DHServerKeyExchange extends TlsServerKeyExchange {
    private final byte[] p;
    private final byte[] g;
    private final byte[] publicKey;
    private DHPublicKey parsedPublicKey;

    public DHServerKeyExchange(TlsKeyExchangeType type, byte[] p, byte[] g, byte[] publicKey) {
        super(type, TlsPreMasterSecretGenerator.dh());
        this.p = p;
        this.g = g;
        this.publicKey = publicKey;
    }

    public DHServerKeyExchange(TlsKeyExchangeType type, ByteBuffer buffer) {
        super(type, TlsPreMasterSecretGenerator.dh());
        this.p = readBytesBigEndian16(buffer);
        this.g = readBytesBigEndian16(buffer);
        this.publicKey = readBytesBigEndian16(buffer);
    }

    @Override
    public void serialize(ByteBuffer buffer) {
        writeBytesBigEndian16(buffer, p);
        writeBytesBigEndian16(buffer, g);
        writeBytesBigEndian16(buffer, publicKey);
    }

    @Override
    public int length() {
        return INT16_LENGTH + p.length
                + INT16_LENGTH + g.length
                + INT16_LENGTH + publicKey.length;
    }

    public byte[] p() {
        return p;
    }

    public byte[] g() {
        return g;
    }

    public byte[] publicKey() {
        return publicKey;
    }

    public DHPublicKey getOrParsePublicKey(DHParameterSpec spec) {
        if(parsedPublicKey != null) {
            return parsedPublicKey;
        }

        try {
            var keyFactory = KeyFactory.getInstance("DH");
            var p = new BigInteger(1, this.p);
            var g = new BigInteger(1, this.g);
            if(!spec.getP().equals(p) || !spec.getG().equals(g)) {
                throw new TlsException("Invalid remote DH public key: parameters mismatch");
            }

            var dhPubKeySpecs = new DHPublicKeySpec(
                    KeyUtils.fromUnsignedLittleEndianBytes(publicKey),
                    p,
                    g
            );
            return parsedPublicKey = (DHPublicKey) keyFactory.generatePublic(dhPubKeySpecs);
        }catch (GeneralSecurityException exception) {
            throw new TlsException("Cannot parse DH key", exception);
        }
    }
}
