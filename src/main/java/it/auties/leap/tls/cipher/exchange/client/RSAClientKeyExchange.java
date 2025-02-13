package it.auties.leap.tls.cipher.exchange.client;

import it.auties.leap.tls.cipher.exchange.TlsClientKeyExchange;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchangeType;
import it.auties.leap.tls.key.TlsPreMasterSecretGenerator;

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
        this.preMasterSecret = readBytesLittleEndian16(buffer);
    }

    @Override
    public void serialize(ByteBuffer buffer) {
        writeBytesLittleEndian16(buffer, preMasterSecret);
    }

    @Override
    public int length() {
        return INT16_LENGTH + preMasterSecret.length;
    }
}