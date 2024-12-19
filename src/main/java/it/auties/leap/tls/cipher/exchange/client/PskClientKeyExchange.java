package it.auties.leap.tls.cipher.exchange.client;

import it.auties.leap.tls.cipher.exchange.TlsKeyExchange;
import it.auties.leap.tls.config.TlsVersion;
import it.auties.leap.tls.key.TlsSupportedGroup;

import java.nio.ByteBuffer;

import static it.auties.leap.tls.BufferHelper.*;

final class PskClientKeyExchange extends TlsKeyExchange.Client {
    private final byte[] pskIdentity;

    PskClientKeyExchange(TlsVersion version, TlsSupportedGroup group) {
        super(version, group);
        this.pskIdentity = null;
    }

    PskClientKeyExchange(ByteBuffer buffer) {
        super(buffer);
        this.pskIdentity = readBytesLittleEndian16(buffer);
    }

    @Override
    public void serialize(ByteBuffer buffer) {
        writeBytesLittleEndian16(buffer, pskIdentity);
    }

    @Override
    public int length() {
        return INT16_LENGTH + pskIdentity.length;
    }
}
