package it.auties.leap.tls.cipher.exchange.server;

import it.auties.leap.tls.cipher.exchange.TlsKeyExchange;

import java.nio.ByteBuffer;

import static it.auties.leap.tls.BufferHelper.INT16_LENGTH;
import static it.auties.leap.tls.BufferHelper.writeBytesLittleEndian16;

public final class PskServerKeyExchange extends TlsKeyExchange.Server {
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
