package it.auties.leap.tls.cipher.exchange;

import it.auties.leap.tls.cipher.exchange.client.TlsClientKeyExchange;
import it.auties.leap.tls.cipher.exchange.server.TlsServerKeyExchange;

import java.nio.ByteBuffer;
import java.security.PrivateKey;

public sealed interface TlsKeyExchange permits TlsClientKeyExchange, TlsServerKeyExchange {
    void serialize(ByteBuffer buffer);
    int length();


    byte[] generatePreMasterSecret(PrivateKey privateKey, ByteBuffer source);
}
