package it.auties.leap.tls.ciphersuite.exchange;

import it.auties.leap.tls.connection.TlsConnectionSecret;
import it.auties.leap.tls.context.TlsContext;

import java.nio.ByteBuffer;

public interface TlsKeyExchange {
    TlsKeyExchangeType type();
    TlsConnectionSecret generatePreSharedSecret(TlsContext context);
    void serialize(ByteBuffer buffer);
    int length();
}
