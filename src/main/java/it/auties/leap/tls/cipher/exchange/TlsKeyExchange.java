package it.auties.leap.tls.cipher.exchange;

import it.auties.leap.tls.cipher.exchange.client.TlsClientKeyExchange;
import it.auties.leap.tls.cipher.exchange.server.TlsServerKeyExchange;
import it.auties.leap.tls.secret.TlsPreMasterSecretGenerator;

import java.nio.ByteBuffer;

public sealed abstract class TlsKeyExchange permits TlsClientKeyExchange, TlsServerKeyExchange {
    protected final TlsKeyExchangeType type;
    protected final TlsPreMasterSecretGenerator preMasterSecretGenerator;

    protected TlsKeyExchange(TlsKeyExchangeType type, TlsPreMasterSecretGenerator preMasterSecretGenerator) {
        this.type = type;
        this.preMasterSecretGenerator = preMasterSecretGenerator;
    }

    public TlsKeyExchangeType type() {
        return type;
    }

    public TlsPreMasterSecretGenerator preMasterSecretGenerator() {
        return preMasterSecretGenerator;
    }

    public abstract void serialize(ByteBuffer buffer);
    public abstract int length();
}
