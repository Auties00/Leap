package it.auties.leap.tls.cipher.exchange.client.implementation;

import it.auties.leap.tls.cipher.exchange.client.TlsClientKeyExchange;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchangeType;
import it.auties.leap.tls.secret.TlsPreMasterSecretGenerator;

import java.nio.ByteBuffer;

import static it.auties.leap.tls.util.BufferUtils.*;

public final class RSAClientKeyExchange extends TlsClientKeyExchange {
    private final byte[] preMasterSecret;

    public RSAClientKeyExchange(byte[] preMasterSecret) {
        super(TlsKeyExchangeType.EPHEMERAL, TlsPreMasterSecretGenerator.rsa());
        this.preMasterSecret = preMasterSecret;
    }

    public RSAClientKeyExchange(ByteBuffer buffer) {
        super(TlsKeyExchangeType.EPHEMERAL, TlsPreMasterSecretGenerator.rsa());
        this.preMasterSecret = readBytesBigEndian16(buffer);
    }

    @Override
    public void serialize(ByteBuffer buffer) {
        writeBytesBigEndian16(buffer, preMasterSecret);
    }

    @Override
    public int length() {
        return INT16_LENGTH + preMasterSecret.length;
    }
}