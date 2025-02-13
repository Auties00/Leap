package it.auties.leap.tls.cipher.exchange.server;

import it.auties.leap.tls.cipher.exchange.TlsKeyExchangeType;
import it.auties.leap.tls.cipher.exchange.TlsServerKeyExchange;
import it.auties.leap.tls.exception.TlsException;
import it.auties.leap.tls.key.TlsPreMasterSecretGenerator;
import it.auties.leap.tls.util.KeyUtils;

import javax.crypto.interfaces.DHPublicKey;
import java.nio.ByteBuffer;
import java.security.PublicKey;

import static it.auties.leap.tls.util.BufferUtils.*;

public final class DHServerKeyExchange extends TlsServerKeyExchange {
    private final byte[] p;
    private final byte[] g;
    private final byte[] y;

    public DHServerKeyExchange(TlsKeyExchangeType type, PublicKey publicKey) {
        if(!(publicKey instanceof DHPublicKey dhPublicKey)) {
            throw new TlsException("Invalid DH public key");
        }

        super(type, TlsPreMasterSecretGenerator.dh());
        this.p = KeyUtils.toUnsignedLittleEndianBytes(dhPublicKey.getParams().getP());
        this.g = KeyUtils.toUnsignedLittleEndianBytes(dhPublicKey.getParams().getG());
        this.y = KeyUtils.toUnsignedLittleEndianBytes(dhPublicKey.getY());
    }

    public DHServerKeyExchange(TlsKeyExchangeType type, ByteBuffer buffer) {
        super(type, TlsPreMasterSecretGenerator.dh());
        this.p = readBytesLittleEndian16(buffer);
        this.g = readBytesLittleEndian16(buffer);
        this.y = readBytesLittleEndian16(buffer);
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

    public byte[] p() {
        return p;
    }

    public byte[] g() {
        return g;
    }

    public byte[] y() {
        return y;
    }
}
