package it.auties.leap.tls.cipher.exchange;

import it.auties.leap.tls.secret.TlsPreMasterSecretGenerator;

import java.nio.ByteBuffer;

public interface TlsKeyExchange {
    TlsKeyExchangeType type();
    TlsPreMasterSecretGenerator preMasterSecretGenerator();
    void serialize(ByteBuffer buffer);
    int length();
}
