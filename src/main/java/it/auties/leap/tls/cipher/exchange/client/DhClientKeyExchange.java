package it.auties.leap.tls.cipher.exchange.client;

import it.auties.leap.tls.cipher.exchange.TlsKeyExchangeType;
import it.auties.leap.tls.config.TlsVersion;
import it.auties.leap.tls.key.TlsKeyPair;
import it.auties.leap.tls.key.TlsSupportedGroup;

import java.nio.ByteBuffer;

import static it.auties.leap.tls.BufferHelper.*;

public final class DhClientKeyExchange extends TlsKeyExchangeType.TlsClientKeyExchange {
    private final TlsKeyPair keyPair;

    DhClientKeyExchange(TlsVersion version, TlsSupportedGroup group) {
        super(version, group);
        this.keyPair = group.generateKeyPair(version);
    }

    DhClientKeyExchange(ByteBuffer buffer) {
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

    public TlsKeyPair tlsKeyPair() {
        return keyPair;
    }
}
