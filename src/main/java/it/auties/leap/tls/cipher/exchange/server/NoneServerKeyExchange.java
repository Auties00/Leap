package it.auties.leap.tls.cipher.exchange.server;

import it.auties.leap.tls.cipher.exchange.TlsKeyExchangeType;
import it.auties.leap.tls.cipher.exchange.TlsServerKeyExchange;
import it.auties.leap.tls.key.TlsPreMasterSecretGenerator;

import java.nio.ByteBuffer;

public final class NoneServerKeyExchange extends TlsServerKeyExchange {
    private static final NoneServerKeyExchange INSTANCE = new NoneServerKeyExchange();

    private NoneServerKeyExchange() {
        super(TlsKeyExchangeType.EPHEMERAL, TlsPreMasterSecretGenerator.none());
    }

    public static NoneServerKeyExchange instance() {
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