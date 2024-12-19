package it.auties.leap.tls.cipher.exchange.client;

import it.auties.leap.tls.cipher.exchange.TlsKeyExchange;
import it.auties.leap.tls.config.TlsVersion;
import it.auties.leap.tls.key.TlsSupportedGroup;

import java.nio.ByteBuffer;

import static it.auties.leap.tls.BufferHelper.*;

final class RsaClientKeyExchange extends TlsKeyExchange.Client {
    private final byte[] extendedPreMasterSecret;

    RsaClientKeyExchange(TlsVersion version, TlsSupportedGroup group) {
        super(version, group);
        this.extendedPreMasterSecret = null;
    }

    RsaClientKeyExchange(ByteBuffer buffer) {
        super(buffer);
        this.extendedPreMasterSecret = readBytesLittleEndian16(buffer);
    }

    @Override
    public void serialize(ByteBuffer buffer) {
        writeBytesLittleEndian16(buffer, extendedPreMasterSecret);
    }

    @Override
    public int length() {
        return INT16_LENGTH + extendedPreMasterSecret.length;
    }
}
