package it.auties.leap.tls.cipher.exchange.client;

import it.auties.leap.tls.cipher.exchange.TlsClientKeyExchange;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchangeType;
import it.auties.leap.tls.key.TlsPreMasterSecretGenerator;

import java.nio.ByteBuffer;

public final class NoneClientKeyExchange extends TlsClientKeyExchange {
    private static final NoneClientKeyExchange INSTANCE = new NoneClientKeyExchange();

    private NoneClientKeyExchange() {
        super(TlsKeyExchangeType.EPHEMERAL, TlsPreMasterSecretGenerator.none());
    }

    public static NoneClientKeyExchange instance() {
        return INSTANCE;
    }

    @Override
    public void serialize(ByteBuffer buffer) {

    }

    @Override
    public int length() {
        return 0;
    }
}