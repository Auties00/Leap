package it.auties.leap.tls.cipher.exchange.client;

import it.auties.leap.tls.cipher.exchange.TlsClientKeyExchange;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchangeType;
import it.auties.leap.tls.exception.TlsException;
import it.auties.leap.tls.key.TlsPreMasterSecretGenerator;

import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHPublicKeySpec;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;

import static it.auties.leap.tls.util.BufferUtils.*;

// This structure conveys the client's Diffie-Hellman public value
//       (Yc) if it was not already included in the client's certificate.
//       The encoding used for Yc is determined by the enumerated
//       PublicValueEncoding. This structure is a variant of the client
//       key exchange message, not a message in itself.
public final class DHClientKeyExchange extends TlsClientKeyExchange {
    private final byte[] publicKey;
    private DHPublicKey parsedPublicKey;

    public DHClientKeyExchange(TlsKeyExchangeType type, byte[] publicKey) {
        super(type, TlsPreMasterSecretGenerator.dh());
        this.publicKey = publicKey;
    }

    public DHClientKeyExchange(TlsKeyExchangeType type, ByteBuffer buffer) {
        super(type, TlsPreMasterSecretGenerator.dh());
        this.publicKey = readBytesBigEndian16(buffer);
    }

    @Override
    public void serialize(ByteBuffer buffer) {
        writeBytesBigEndian16(buffer, publicKey);
    }

    @Override
    public int length() {
        return INT16_LENGTH + publicKey.length;
    }

    public byte[] publicKey() {
        return publicKey;
    }

    public DHPublicKey getOrParsePublicKey(BigInteger p, BigInteger g) {
        if(parsedPublicKey != null) {
            return parsedPublicKey;
        }

        try {
            var keyFactory = KeyFactory.getInstance("DH");
            var dhPubKeySpecs = new DHPublicKeySpec(
                    new BigInteger(1, publicKey),
                    p,
                    g
            );
            return parsedPublicKey = (DHPublicKey) keyFactory.generatePublic(dhPubKeySpecs);
        }catch (GeneralSecurityException exception) {
            throw new TlsException("Cannot parse DH key", exception);
        }
    }
}
