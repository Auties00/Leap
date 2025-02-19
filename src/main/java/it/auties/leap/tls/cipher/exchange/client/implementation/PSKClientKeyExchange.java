package it.auties.leap.tls.cipher.exchange.client.implementation;

import it.auties.leap.tls.cipher.exchange.client.TlsClientKeyExchange;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchangeType;
import it.auties.leap.tls.secret.TlsPreMasterSecretGenerator;

import java.nio.ByteBuffer;

import static it.auties.leap.tls.util.BufferUtils.*;

public final class PSKClientKeyExchange extends TlsClientKeyExchange {
    private final byte[] identityKey;

    public PSKClientKeyExchange(byte[] identityKey) {
        super(TlsKeyExchangeType.EPHEMERAL, TlsPreMasterSecretGenerator.psk());
        this.identityKey = identityKey;
    }

    public PSKClientKeyExchange(ByteBuffer buffer) {
        super(TlsKeyExchangeType.EPHEMERAL, TlsPreMasterSecretGenerator.psk());
        this.identityKey = readBytesBigEndian16(buffer);
    }

    @Override
    public void serialize(ByteBuffer buffer) {
        writeBytesBigEndian16(buffer, identityKey);
    }

    @Override
    public int length() {
        return INT16_LENGTH + identityKey.length;
    }
}