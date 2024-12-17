package it.auties.leap.tls.cipher.exchange.client;

import it.auties.leap.tls.cipher.exchange.TlsKeyExchangeType;
import it.auties.leap.tls.config.TlsVersion;
import it.auties.leap.tls.key.TlsKeyPair;
import it.auties.leap.tls.key.TlsSupportedGroup;

import java.nio.ByteBuffer;

import static it.auties.leap.tls.BufferHelper.*;

final class GostrClientKeyExchange extends TlsKeyExchangeType.TlsClientKeyExchange {
    private final TlsKeyPair keyPair;
    private final byte[] additionalData;

    GostrClientKeyExchange(TlsVersion version, TlsSupportedGroup group) {
        super(version, group);
        this.keyPair = group.generateKeyPair(version);
        this.additionalData = null;
    }

    GostrClientKeyExchange(ByteBuffer buffer) {
        super(buffer);
        this.keyPair = new TlsKeyPair(readBytesLittleEndian16(buffer));
        this.additionalData = readBytesLittleEndian16(buffer);
    }

    @Override
    public void serialize(ByteBuffer buffer) {
        writeBytesLittleEndian16(buffer, keyPair.publicKey());
        writeBytesLittleEndian16(buffer, additionalData);
    }

    @Override
    public int length() {
        return INT16_LENGTH + keyPair.publicKey().length
                + INT16_LENGTH + additionalData.length;
    }
}
