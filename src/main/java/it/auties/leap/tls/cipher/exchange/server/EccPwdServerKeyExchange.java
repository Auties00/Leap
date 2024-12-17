package it.auties.leap.tls.cipher.exchange.server;

import it.auties.leap.tls.cipher.exchange.TlsKeyExchangeType;
import it.auties.leap.tls.key.TlsSupportedGroup;

import java.nio.ByteBuffer;
import java.util.Objects;

import static it.auties.leap.tls.BufferHelper.*;

public final class EccPwdServerKeyExchange extends TlsKeyExchangeType.TlsServerKeyExchange {
    private final TlsSupportedGroup group;
    private final byte[] element;
    private final byte[] scalar;

    public EccPwdServerKeyExchange(TlsSupportedGroup group, byte[] element, byte[] scalar) {
        this.group = group;
        this.element = element;
        this.scalar = scalar;
    }

    @Override
    public void serialize(ByteBuffer buffer) {
        writeLittleEndianInt16(buffer, group.id());
        writeBytesLittleEndian16(buffer, element);
        writeBytesLittleEndian16(buffer, scalar);
    }

    @Override
    public int length() {
        return INT16_LENGTH
                + INT16_LENGTH + element.length
                + INT16_LENGTH + scalar.length;
    }
}