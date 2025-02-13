package it.auties.leap.tls.cipher.exchange.server;

import it.auties.leap.tls.cipher.exchange.TlsKeyExchangeType;
import it.auties.leap.tls.cipher.exchange.TlsServerKeyExchange;
import it.auties.leap.tls.ec.TlsECParameters;
import it.auties.leap.tls.ec.TlsECParametersDeserializer;
import it.auties.leap.tls.key.TlsPreMasterSecretGenerator;

import java.nio.ByteBuffer;

import static it.auties.leap.tls.util.BufferUtils.*;

public final class ECCPWDServerKeyExchange extends TlsServerKeyExchange {
    private final byte[] salt;
    private final TlsECParameters params;
    private final byte[] publicKey;
    private final byte[] password;

    public ECCPWDServerKeyExchange(byte[] salt, TlsECParameters params, byte[] publicKey, byte[] password) {
        super(TlsKeyExchangeType.EPHEMERAL, TlsPreMasterSecretGenerator.eccpwd());
        this.salt = salt;
        this.params = params;
        this.publicKey = publicKey;
        this.password = password;
    }

    public ECCPWDServerKeyExchange(ByteBuffer buffer, TlsECParametersDeserializer decoder) {
        super(TlsKeyExchangeType.EPHEMERAL, TlsPreMasterSecretGenerator.eccpwd());
        this.salt = readBytesLittleEndian8(buffer);
        this.params = decoder.deserialize(buffer);
        this.publicKey = readBytesLittleEndian8(buffer);
        this.password = readBytesLittleEndian8(buffer);
    }

    @Override
    public void serialize(ByteBuffer buffer) {
        writeBytesLittleEndian16(buffer, salt);
        params.serialize(buffer);
        writeBytesLittleEndian8(buffer, publicKey);
        writeBytesLittleEndian8(buffer, password);
    }

    @Override
    public int length() {
        return INT8_LENGTH + salt.length
                + params.length()
                + INT8_LENGTH + publicKey.length
                + INT8_LENGTH + password.length;
    }
}