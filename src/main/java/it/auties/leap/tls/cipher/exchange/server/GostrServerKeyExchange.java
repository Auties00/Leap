package it.auties.leap.tls.cipher.exchange.server;

import it.auties.leap.tls.cipher.exchange.TlsKeyExchangeType;

import java.nio.ByteBuffer;
import java.util.Objects;

import static it.auties.leap.tls.BufferHelper.*;

public final class GostrServerKeyExchange extends TlsKeyExchangeType.TlsServerKeyExchange {
    private final byte[] paramSet;
    private final byte[] rawPublicKey;

    public GostrServerKeyExchange(byte[] paramSet, byte[] rawPublicKey) {
        this.paramSet = paramSet;
        this.rawPublicKey = rawPublicKey;
    }

    @Override
    public void serialize(ByteBuffer buffer) {
        writeBytesLittleEndian8(buffer, paramSet);
        writeBytesLittleEndian16(buffer, rawPublicKey);
    }

    @Override
    public int length() {
        return INT8_LENGTH + paramSet.length
                + INT16_LENGTH + rawPublicKey.length;
    }
}
