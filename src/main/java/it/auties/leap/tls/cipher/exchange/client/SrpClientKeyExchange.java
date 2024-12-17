package it.auties.leap.tls.cipher.exchange.client;

import it.auties.leap.tls.cipher.exchange.TlsKeyExchangeType;
import it.auties.leap.tls.config.TlsVersion;
import it.auties.leap.tls.key.TlsSupportedGroup;

import java.nio.ByteBuffer;

import static it.auties.leap.tls.BufferHelper.*;

final class SrpClientKeyExchange extends TlsKeyExchangeType.TlsClientKeyExchange {
    private final byte[] srpA;

    SrpClientKeyExchange(TlsVersion version, TlsSupportedGroup group) {
        super(version, group);
        this.srpA = null;
    }

    SrpClientKeyExchange(ByteBuffer buffer) {
        super(buffer);
        this.srpA = readBytesLittleEndian16(buffer);
    }

    @Override
    public void serialize(ByteBuffer buffer) {
        writeBytesLittleEndian16(buffer, srpA);
    }

    @Override
    public int length() {
        return INT16_LENGTH + srpA.length;
    }
}