package it.auties.leap.tls.cipher.exchange.client;

import it.auties.leap.tls.cipher.exchange.TlsKeyExchange;
import it.auties.leap.tls.config.TlsVersion;
import it.auties.leap.tls.key.TlsSupportedGroup;

import java.nio.ByteBuffer;

import static it.auties.leap.tls.BufferHelper.*;

final class Krb5ClientKeyExchange extends TlsKeyExchange.Client {
    private final byte[] ticket;
    private final byte[] additionalData;

    Krb5ClientKeyExchange(TlsVersion version, TlsSupportedGroup group) {
        super(version, group);
        this.ticket = null;
        this.additionalData = null;
    }

    Krb5ClientKeyExchange(ByteBuffer buffer) {
        super(buffer);
        this.ticket = readBytesLittleEndian16(buffer);
        this.additionalData = readBytesLittleEndian16(buffer);
    }

    @Override
    public void serialize(ByteBuffer buffer) {
        writeBytesLittleEndian16(buffer, ticket);
        writeBytesLittleEndian16(buffer, additionalData);
    }

    @Override
    public int length() {
        return INT16_LENGTH + ticket.length
                + INT16_LENGTH + additionalData.length;
    }
}
