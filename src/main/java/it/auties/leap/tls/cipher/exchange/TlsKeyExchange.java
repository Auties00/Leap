package it.auties.leap.tls.cipher.exchange;

import java.nio.ByteBuffer;

public sealed interface TlsKeyExchange permits TlsClientKeyExchange, TlsServerKeyExchange {
    void serialize(ByteBuffer buffer);
    int length();
}
