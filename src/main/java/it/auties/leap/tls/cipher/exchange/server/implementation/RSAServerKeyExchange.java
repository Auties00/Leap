package it.auties.leap.tls.cipher.exchange.server.implementation;

import it.auties.leap.tls.cipher.exchange.TlsKeyExchangeType;
import it.auties.leap.tls.cipher.exchange.server.TlsServerKeyExchange;
import it.auties.leap.tls.secret.TlsPreMasterSecretGenerator;

import java.nio.ByteBuffer;

import static it.auties.leap.tls.util.BufferUtils.*;

public final class RSAServerKeyExchange extends TlsServerKeyExchange {
    private final byte[] modulus;
    private final byte[] exponent;

    public RSAServerKeyExchange(byte[] modulus, byte[] exponent) {
        super(TlsKeyExchangeType.EPHEMERAL, TlsPreMasterSecretGenerator.rsa());
        this.modulus = modulus;
        this.exponent = exponent;
    }

    public RSAServerKeyExchange(ByteBuffer buffer) {
        super(TlsKeyExchangeType.EPHEMERAL, TlsPreMasterSecretGenerator.rsa());
        this.modulus = readBytesBigEndian16(buffer);
        this.exponent = readBytesBigEndian16(buffer);
    }

    @Override
    public void serialize(ByteBuffer buffer) {
        writeBytesBigEndian16(buffer, modulus);
        writeBytesBigEndian16(buffer, exponent);
    }

    @Override
    public int length() {
        return INT16_LENGTH + modulus.length
                + INT16_LENGTH + exponent.length;
    }
}