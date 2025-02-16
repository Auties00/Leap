package it.auties.leap.tls.cipher.exchange.server;

import it.auties.leap.tls.cipher.exchange.TlsKeyExchangeType;
import it.auties.leap.tls.cipher.exchange.TlsServerKeyExchange;
import it.auties.leap.tls.ec.TlsECParameters;
import it.auties.leap.tls.exception.TlsException;
import it.auties.leap.tls.key.TlsPreMasterSecretGenerator;
import it.auties.leap.tls.key.TlsSupportedGroup;

import java.nio.ByteBuffer;
import java.util.List;

import static it.auties.leap.tls.util.BufferUtils.*;

public class ECDHServerKeyExchange extends TlsServerKeyExchange {
    protected final TlsECParameters parameters;
    protected final byte[] publicKey;

    public ECDHServerKeyExchange(TlsKeyExchangeType type, TlsECParameters parameters, byte[] publicKey) {
        super(type, TlsPreMasterSecretGenerator.ecdh());
        this.parameters = parameters;
        this.publicKey = publicKey;
    }

    public ECDHServerKeyExchange(TlsKeyExchangeType type, ByteBuffer buffer, List<TlsSupportedGroup> supportedGroups) {
        super(type, TlsPreMasterSecretGenerator.ecdh());
        this.parameters = decodeParams(buffer, supportedGroups);
        this.publicKey = readBytesBigEndian8(buffer);
    }

    private TlsECParameters decodeParams(ByteBuffer buffer, List<TlsSupportedGroup> supportedGroups) {
        var ecType = readBigEndianInt8(buffer);
        for(var supportedGroup : supportedGroups) {
            var decoder = supportedGroup.ellipticCurveParametersDeserializer()
                    .orElse(null);
            if(decoder != null && decoder.type() == ecType) {
                return decoder.deserialize(buffer);
            }
        }
        throw new TlsException("Cannot decode parameters, no decoder for ec curve type: " + ecType);
    }

    @Override
    public void serialize(ByteBuffer buffer) {
        writeBytesBigEndian8(buffer, publicKey);
    }

    @Override
    public int length() {
        return parameters.length()
                + INT8_LENGTH + publicKey.length;
    }

    public byte[] publicKey() {
        return publicKey;
    }

    public TlsECParameters parameters() {
        return parameters;
    }
}
