package it.auties.leap.tls.cipher.exchange.client.implementation;

import it.auties.leap.tls.cipher.exchange.client.TlsClientKeyExchange;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchangeType;
import it.auties.leap.tls.secret.TlsPreMasterSecretGenerator;

import java.nio.ByteBuffer;

import static it.auties.leap.tls.util.BufferUtils.*;

public final class ECDHClientKeyExchange extends TlsClientKeyExchange {
    private final byte[] publicKey;

    public ECDHClientKeyExchange(TlsKeyExchangeType type, byte[] publicKey) {
        super(type, TlsPreMasterSecretGenerator.ecdh());
        this.publicKey = publicKey;
    }

    public ECDHClientKeyExchange(TlsKeyExchangeType type, ByteBuffer buffer) {
        super(type, TlsPreMasterSecretGenerator.ecdh());
        this.publicKey = readBytesBigEndian8(buffer);
    }

    @Override
    public void serialize(ByteBuffer buffer) {
        writeBytesBigEndian8(buffer, publicKey);
    }

    @Override
    public int length() {
        return INT8_LENGTH + publicKey.length;
    }

    public byte[] publicKey() {
        return publicKey;
    }
}
