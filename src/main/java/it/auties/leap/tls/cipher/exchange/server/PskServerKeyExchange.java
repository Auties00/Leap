package it.auties.leap.tls.cipher.exchange.server;

import it.auties.leap.tls.cipher.exchange.TlsKeyExchangeType;

import java.nio.ByteBuffer;
import java.util.Objects;

import static it.auties.leap.tls.BufferHelper.INT16_LENGTH;
import static it.auties.leap.tls.BufferHelper.writeBytesLittleEndian16;

public final class PskServerKeyExchange extends TlsKeyExchangeType.TlsServerKeyExchange {
    private final byte[] identityHint;

    public PskServerKeyExchange(byte[] identityHint) {
        this.identityHint = identityHint;
    }

    @Override
    public void serialize(ByteBuffer buffer) {
        writeBytesLittleEndian16(buffer, identityHint);
    }

    @Override
    public int length() {
        return INT16_LENGTH + identityHint.length;
    }
}
