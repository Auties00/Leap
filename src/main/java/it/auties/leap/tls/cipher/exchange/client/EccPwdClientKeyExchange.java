package it.auties.leap.tls.cipher.exchange.client;

import it.auties.leap.tls.cipher.exchange.TlsKeyExchange;
import it.auties.leap.tls.config.TlsVersion;
import it.auties.leap.tls.key.TlsKeyPair;
import it.auties.leap.tls.key.TlsSupportedGroup;

import java.nio.ByteBuffer;

import static it.auties.leap.tls.BufferHelper.*;

final class EccPwdClientKeyExchange extends TlsKeyExchange.Client {
    private final byte[] password;
    private final TlsKeyPair keyPair;

    EccPwdClientKeyExchange(TlsVersion version, TlsSupportedGroup group) {
        super(version, group);
        this.keyPair = group.generateKeyPair(version);
        this.password = null;
    }

    EccPwdClientKeyExchange(ByteBuffer buffer) {
        super(buffer);
        this.password = readBytesLittleEndian8(buffer);
        this.keyPair = TlsKeyPair.of(readBytesLittleEndian8(buffer));
    }

    @Override
    public void serialize(ByteBuffer buffer) {
        writeBytesLittleEndian8(buffer, password);
        writeBytesLittleEndian8(buffer, keyPair.publicKey());
    }

    @Override
    public int length() {
        return INT8_LENGTH + password.length
                + INT8_LENGTH + keyPair.publicKey().length;
    }
}
