package it.auties.leap.tls.cipher.exchange.client;

import it.auties.leap.tls.cipher.exchange.TlsClientKeyExchange;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchangeType;
import it.auties.leap.tls.key.TlsPreMasterSecretGenerator;

import java.nio.ByteBuffer;

import static it.auties.leap.tls.util.BufferUtils.*;

//  For ECC cipher suites, this indicates whether
//      the client's ECDH public key is in the client's certificate
//      ("implicit") or is provided, as an ephemeral ECDH public key, in
//      the ClientKeyExchange message ("explicit").  (This is "explicit"
//      in ECC cipher suites except when the client uses the
//      ECDSA_fixed_ECDH or RSA_fixed_ECDH client authentication
//      mechanism.)
public final class ECDHClientKeyExchange extends TlsClientKeyExchange {
    private final byte[] publicKey;

    public ECDHClientKeyExchange(TlsKeyExchangeType type, byte[] publicKey) {
        super(type, TlsPreMasterSecretGenerator.ecdh());
        this.publicKey = publicKey;
    }

    public ECDHClientKeyExchange(TlsKeyExchangeType type, ByteBuffer buffer) {
        super(type, TlsPreMasterSecretGenerator.ecdh());
        this.publicKey = readBytesLittleEndian8(buffer);
    }

    @Override
    public void serialize(ByteBuffer buffer) {
        writeBytesLittleEndian8(buffer, publicKey);
    }

    @Override
    public int length() {
        return INT8_LENGTH + publicKey.length;
    }

    public byte[] publicKey() {
        return publicKey;
    }
}
