package it.auties.leap.tls.cipher.exchange.client;

import it.auties.leap.tls.cipher.exchange.TlsKeyExchangeType;
import it.auties.leap.tls.config.TlsVersion;
import it.auties.leap.tls.key.TlsKeyPair;
import it.auties.leap.tls.key.TlsSupportedGroup;

import java.nio.ByteBuffer;

import static it.auties.leap.tls.BufferHelper.*;

final class EcDhClientKeyExchange extends TlsKeyExchangeType.TlsClientKeyExchange {
    private final TlsKeyPair keyPair;

    EcDhClientKeyExchange(TlsVersion version, TlsSupportedGroup group) {
        super(version, group);
        this.keyPair = group.generateKeyPair(version);
    }

    EcDhClientKeyExchange(ByteBuffer buffer) {
        super(buffer);
        this.keyPair = new TlsKeyPair(readBytesLittleEndian8(buffer));
    }

    @Override
    public void serialize(ByteBuffer buffer) {
        writeBytesLittleEndian8(buffer, keyPair.publicKey());
    }

    @Override
    public int length() {
        return INT8_LENGTH + keyPair.publicKey().length;
    }
}
