package it.auties.leap.tls.cipher.exchange.client;

import it.auties.leap.tls.cipher.exchange.TlsKeyExchangeType;
import it.auties.leap.tls.config.TlsVersion;
import it.auties.leap.tls.key.TlsSupportedGroup;

import java.nio.ByteBuffer;

public class NoneClientKeyExchange extends TlsKeyExchangeType.TlsClientKeyExchange {
    protected NoneClientKeyExchange(TlsVersion version, TlsSupportedGroup group) {
        super(version, group);
    }

    protected NoneClientKeyExchange(ByteBuffer buffer) {
        super(buffer);
    }

    @Override
    public void serialize(ByteBuffer buffer) {

    }

    @Override
    public int length() {
        return 0;
    }
}
