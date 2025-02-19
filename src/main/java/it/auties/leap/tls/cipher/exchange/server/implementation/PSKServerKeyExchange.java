package it.auties.leap.tls.cipher.exchange.server.implementation;

import it.auties.leap.tls.cipher.exchange.TlsKeyExchangeType;
import it.auties.leap.tls.cipher.exchange.server.TlsServerKeyExchange;
import it.auties.leap.tls.secret.TlsPreMasterSecretGenerator;

import java.nio.ByteBuffer;

import static it.auties.leap.tls.util.BufferUtils.*;

public final class PSKServerKeyExchange extends TlsServerKeyExchange {
    private final byte[] identityKeyHint;

    public PSKServerKeyExchange(byte[] identityKeyHint) {
        super(TlsKeyExchangeType.EPHEMERAL, TlsPreMasterSecretGenerator.psk());
        this.identityKeyHint = identityKeyHint;
    }

    public PSKServerKeyExchange(ByteBuffer buffer) {
        this(readBytesBigEndian16(buffer));
    }

    @Override
    public void serialize(ByteBuffer buffer) {
        writeBytesBigEndian16(buffer, identityKeyHint);
    }

    @Override
    public int length() {
        return INT16_LENGTH + identityKeyHint.length;
    }
}