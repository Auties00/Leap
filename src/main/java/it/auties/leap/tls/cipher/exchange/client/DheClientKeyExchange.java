package it.auties.leap.tls.cipher.exchange.client;

import it.auties.leap.tls.cipher.exchange.TlsKeyExchange;
import it.auties.leap.tls.config.TlsVersion;
import it.auties.leap.tls.key.TlsKeyPair;
import it.auties.leap.tls.key.TlsSupportedGroup;

import java.nio.ByteBuffer;

import static it.auties.leap.tls.BufferHelper.*;

final class DheClientKeyExchange extends TlsKeyExchange.Client {
    private final TlsKeyPair keyPair;

    DheClientKeyExchange(TlsVersion version, TlsSupportedGroup group) {
        super(version, group);
        this.keyPair = group.generateKeyPair(version);
    }

    DheClientKeyExchange(ByteBuffer buffer) {
        super(buffer);
        this.keyPair = TlsKeyPair.of(readBytesLittleEndian16(buffer));
    }

    @Override
    public void serialize(ByteBuffer buffer) {
        writeBytesLittleEndian16(buffer, keyPair.publicKey());
    }

    @Override
    public int length() {
        return INT16_LENGTH + keyPair.publicKey().length;
    }
}
