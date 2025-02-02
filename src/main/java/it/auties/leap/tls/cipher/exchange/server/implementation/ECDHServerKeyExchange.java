package it.auties.leap.tls.cipher.exchange.server.implementation;

import it.auties.leap.tls.cipher.exchange.TlsKeyExchange;
import it.auties.leap.tls.cipher.exchange.client.TlsClientKeyExchange;
import it.auties.leap.tls.cipher.exchange.client.implementation.ECDHClientKeyExchange;
import it.auties.leap.tls.cipher.exchange.server.TlsServerKeyExchange;
import it.auties.leap.tls.cipher.exchange.server.TlsServerKeyExchangeFactory;
import it.auties.leap.tls.ec.TlsECParameters;
import it.auties.leap.tls.ec.TlsECParametersDecoder;
import it.auties.leap.tls.exception.TlsException;

import javax.crypto.KeyAgreement;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.List;

import static it.auties.leap.tls.util.BufferUtils.*;

public class ECDHServerKeyExchange implements TlsServerKeyExchange {
    private static final TlsServerKeyExchangeFactory FACTORY = engine -> {
        var publicKey = engine.localKeyPair()
                .map(keyPair -> keyPair.getPublic().getEncoded())
                .orElseThrow(() -> new TlsException("Missing key pair"));
        return new ECDHServerKeyExchange(null, publicKey);
    };

    protected final TlsECParameters params;
    protected final byte[] publicKey;

    public ECDHServerKeyExchange(TlsECParameters params, byte[] publicKey) {
        this.params = params;
        this.publicKey = publicKey;
    }

    public ECDHServerKeyExchange(ByteBuffer buffer, TlsECParametersDecoder decoder) {
        var ecType = readLittleEndianInt8(buffer);
        if(ecType != decoder.id()) {
            throw new TlsException("Cannot decode parameters, no decoder for ec curve type: " + ecType);
        }
        this.params = decoder.decode(buffer);
        this.publicKey = readBytesLittleEndian8(buffer);
    }

    public ECDHServerKeyExchange(ByteBuffer buffer, List<TlsECParametersDecoder> decoders) {
        this.params = decodeParams(buffer, decoders);
        this.publicKey = readBytesLittleEndian8(buffer);
    }

    private TlsECParameters decodeParams(ByteBuffer buffer, List<TlsECParametersDecoder> decoders) {
        var ecType = readLittleEndianInt8(buffer);
        for(var decoder : decoders) {
            if(decoder.id() == ecType) {
                return decoder.decode(buffer);
            }
        }
        throw new TlsException("Cannot decode parameters, no decoder for ec curve type: " + ecType);
    }

    public static TlsServerKeyExchangeFactory factory() {
        return FACTORY;
    }

    @Override
    public void serialize(ByteBuffer buffer) {
        writeBytesLittleEndian8(buffer, publicKey);
    }

    @Override
    public int length() {
        return params.length()
                + INT8_LENGTH + publicKey.length;
    }

    @Override
    public TlsServerKeyExchange decodeLocal(ByteBuffer buffer) {
        return new ECDHServerKeyExchange(buffer, params.decoder());
    }

    @Override
    public TlsClientKeyExchange decodeRemote(ByteBuffer buffer) {
        return new ECDHClientKeyExchange(buffer, List.of(params.decoder()));
    }

    @Override
    public byte[] generatePreMasterSecret(PrivateKey localPrivateKey, PublicKey remoteCertificatePublicKey, TlsKeyExchange remoteKeyExchange) {
        try {
            var keyAgreement = KeyAgreement.getInstance("ECDH");
            keyAgreement.init(localPrivateKey);
            keyAgreement.doPhase(null, true);
            return keyAgreement.generateSecret();
        } catch (GeneralSecurityException exception) {
            throw new TlsException("Cannot generate pre master secret", exception);
        }
    }
}
