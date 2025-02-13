package it.auties.leap.tls.cipher.exchange.server;

import it.auties.leap.tls.cipher.exchange.TlsKeyExchangeType;
import it.auties.leap.tls.cipher.exchange.TlsServerKeyExchange;
import it.auties.leap.tls.key.TlsPreMasterSecretGenerator;

import java.nio.ByteBuffer;

import static it.auties.leap.tls.util.BufferUtils.*;

public final class PSKServerKeyExchange extends TlsServerKeyExchange {
    private final byte[] identityKeyHint;

    public PSKServerKeyExchange(byte[] identityKeyHint) {
        super(TlsKeyExchangeType.EPHEMERAL, TlsPreMasterSecretGenerator.psk());
        this.identityKeyHint = identityKeyHint;
    }

    public PSKServerKeyExchange(ByteBuffer buffer) {
        this(readBytesLittleEndian16(buffer));
    }

    @Override
    public void serialize(ByteBuffer buffer) {
        writeBytesLittleEndian16(buffer, identityKeyHint);
    }

    @Override
    public int length() {
        return INT16_LENGTH + identityKeyHint.length;
    }
}