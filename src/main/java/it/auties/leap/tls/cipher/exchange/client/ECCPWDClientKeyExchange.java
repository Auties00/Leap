package it.auties.leap.tls.cipher.exchange.client;

import it.auties.leap.tls.cipher.exchange.TlsClientKeyExchange;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchangeType;
import it.auties.leap.tls.key.TlsPreMasterSecretGenerator;

import java.nio.ByteBuffer;

import static it.auties.leap.tls.util.BufferUtils.*;

public final class ECCPWDClientKeyExchange extends TlsClientKeyExchange {
    private final byte[] publicKey;
    private final byte[] password;

    public ECCPWDClientKeyExchange(byte[] publicKey, byte[] password) {
        super(TlsKeyExchangeType.EPHEMERAL, TlsPreMasterSecretGenerator.eccpwd());
        this.password = password;
        this.publicKey = publicKey;
    }

    public ECCPWDClientKeyExchange(ByteBuffer buffer) {
        super(TlsKeyExchangeType.EPHEMERAL, TlsPreMasterSecretGenerator.eccpwd());
        this.publicKey = readBytesBigEndian8(buffer);
        this.password = readBytesBigEndian8(buffer);
    }

    @Override
    public void serialize(ByteBuffer buffer) {
        writeBytesBigEndian8(buffer, publicKey);
        writeBytesBigEndian8(buffer, password);
    }

    @Override
    public int length() {
        return INT8_LENGTH + publicKey.length +
                INT8_LENGTH + password.length;
    }
}