package it.auties.leap.tls.cipher.exchange.server;

import it.auties.leap.tls.cipher.exchange.TlsKeyExchangeType;
import it.auties.leap.tls.cipher.exchange.TlsServerKeyExchange;
import it.auties.leap.tls.key.TlsPreMasterSecretGenerator;

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
        this.modulus = readBytesLittleEndian16(buffer);
        this.exponent = readBytesLittleEndian16(buffer);
    }

    @Override
    public void serialize(ByteBuffer buffer) {
        writeBytesLittleEndian16(buffer, modulus);
        writeBytesLittleEndian16(buffer, exponent);
    }

    @Override
    public int length() {
        return INT16_LENGTH + modulus.length
                + INT16_LENGTH + exponent.length;
    }
}