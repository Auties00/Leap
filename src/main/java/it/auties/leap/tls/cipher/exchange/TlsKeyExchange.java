package it.auties.leap.tls.cipher.exchange;

import it.auties.leap.tls.cipher.exchange.client.TlsClientKeyExchange;
import it.auties.leap.tls.cipher.exchange.server.TlsServerKeyExchange;

import java.nio.ByteBuffer;
import java.security.PrivateKey;
import java.security.PublicKey;

public sealed interface TlsKeyExchange permits TlsClientKeyExchange, TlsServerKeyExchange {
    void serialize(ByteBuffer buffer);
    int length();


    byte[] generatePreMasterSecret(PrivateKey localPrivateKey, PublicKey remoteCertificatePublicKey, TlsKeyExchange remoteKeyExchange);

    TlsKeyExchange decodeLocal(ByteBuffer buffer);
    TlsKeyExchange decodeRemote(ByteBuffer buffer);
}
