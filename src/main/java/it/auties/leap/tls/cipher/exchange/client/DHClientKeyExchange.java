package it.auties.leap.tls.cipher.exchange.client;

import it.auties.leap.tls.cipher.exchange.TlsClientKeyExchange;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchangeType;
import it.auties.leap.tls.exception.TlsException;
import it.auties.leap.tls.key.TlsPreMasterSecretGenerator;

import javax.crypto.interfaces.DHPublicKey;
import java.nio.ByteBuffer;
import java.security.PublicKey;

import static it.auties.leap.tls.util.BufferUtils.*;
import static it.auties.leap.tls.util.KeyUtils.toUnsignedLittleEndianBytes;

// This structure conveys the client's Diffie-Hellman public value
//       (Yc) if it was not already included in the client's certificate.
//       The encoding used for Yc is determined by the enumerated
//       PublicValueEncoding. This structure is a variant of the client
//       key exchange message, not a message in itself.
public final class DHClientKeyExchange extends TlsClientKeyExchange {
    private final byte[] y;

    public DHClientKeyExchange(TlsKeyExchangeType type, PublicKey publicKey) {
        if(!(publicKey instanceof DHPublicKey dhPublicKey)) {
            throw new TlsException("Invalid DH public key");
        }

        super(type, TlsPreMasterSecretGenerator.dh());
        this.y = toUnsignedLittleEndianBytes(dhPublicKey.getY());
    }

    public DHClientKeyExchange(TlsKeyExchangeType type, ByteBuffer buffer) {
        super(type, TlsPreMasterSecretGenerator.dh());
        this.y = readBytesLittleEndian8(buffer);
    }

    @Override
    public void serialize(ByteBuffer buffer) {
        writeBytesLittleEndian8(buffer, y);
    }

    @Override
    public int length() {
        return INT8_LENGTH + y.length;
    }

    public byte[] y() {
        return y;
    }
}
