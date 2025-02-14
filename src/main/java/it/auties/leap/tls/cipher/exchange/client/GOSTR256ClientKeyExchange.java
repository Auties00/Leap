package it.auties.leap.tls.cipher.exchange.client;

import it.auties.leap.tls.cipher.exchange.TlsClientKeyExchange;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchangeType;
import it.auties.leap.tls.key.TlsPreMasterSecretGenerator;

import java.nio.ByteBuffer;

import static it.auties.leap.tls.util.BufferUtils.*;;

// https://www.ietf.org/archive/id/draft-smyshlyaev-tls12-gost-suites-18.html
public final class GOSTR256ClientKeyExchange extends TlsClientKeyExchange {
    private final byte[] encodedKeyTransport;

    public GOSTR256ClientKeyExchange(byte[] encodedKeyTransport) {
        super(TlsKeyExchangeType.EPHEMERAL, TlsPreMasterSecretGenerator.gostr256());
        this.encodedKeyTransport = encodedKeyTransport;
    }

    @Override
    public void serialize(ByteBuffer buffer) {
        writeBytes(buffer, encodedKeyTransport);
    }

    @Override
    public int length() {
        return encodedKeyTransport.length;
    }
}