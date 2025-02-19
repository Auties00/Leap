package it.auties.leap.tls.cipher.exchange.client.implementation;

import it.auties.leap.tls.cipher.exchange.TlsKeyExchangeType;
import it.auties.leap.tls.cipher.exchange.client.TlsClientKeyExchange;
import it.auties.leap.tls.secret.TlsPreMasterSecretGenerator;

import java.nio.ByteBuffer;

import static it.auties.leap.tls.util.BufferUtils.*;

public final class SRPClientKeyExchange extends TlsClientKeyExchange {
    private final byte[] srpA;

    public SRPClientKeyExchange(byte[] srpA) {
        super(TlsKeyExchangeType.EPHEMERAL, TlsPreMasterSecretGenerator.srp());
        this.srpA = srpA;
    }

    public SRPClientKeyExchange(ByteBuffer buffer) {
        super(TlsKeyExchangeType.EPHEMERAL, TlsPreMasterSecretGenerator.srp());
        this.srpA = readBytesBigEndian16(buffer);
    }

    @Override
    public void serialize(ByteBuffer buffer) {
        writeBytesBigEndian16(buffer, srpA);
    }

    @Override
    public int length() {
        return INT16_LENGTH + srpA.length;
    }
}