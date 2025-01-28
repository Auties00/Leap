package it.auties.leap.tls.extension.implementation;

import it.auties.leap.tls.TlsEngine;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.extension.TlsExtensionDecoder;
import it.auties.leap.tls.signature.TlsSignature;
import it.auties.leap.tls.signature.TlsSignatureAlgorithm;
import it.auties.leap.tls.signature.TlsSignatureScheme;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static it.auties.leap.tls.signature.TlsSignatureAlgorithm.Hash.*;
import static it.auties.leap.tls.signature.TlsSignatureAlgorithm.Signature.*;
import static it.auties.leap.tls.signature.TlsSignatureScheme.*;
import static it.auties.leap.tls.util.BufferUtils.*;

public record SignatureAlgorithmsExtension(
        List<Integer> algorithms
) implements TlsExtension.Concrete {
    private static final TlsExtensionDecoder DECODER = new TlsExtensionDecoder() {
        @Override
        public Optional<? extends Concrete> decode(ByteBuffer buffer, int type, TlsEngine.Mode mode) {
            var algorithmsSize = readLittleEndianInt16(buffer);
            var algorithms = new ArrayList<Integer>(algorithmsSize);
            for (var i = 0; i < algorithmsSize; i++) {
                var algorithmId = readLittleEndianInt16(buffer);
                algorithms.add(algorithmId);
            }
            var extension = new SignatureAlgorithmsExtension(algorithms);
            return Optional.of(extension);
        }

        @Override
        public Class<? extends Concrete> toConcreteType(TlsEngine.Mode mode) {
            return SignatureAlgorithmsExtension.class;
        }
    };

    private static final SignatureAlgorithmsExtension RECOMMENDED = new SignatureAlgorithmsExtension(List.of(
            ecdsaSecp256r1Sha256().id(),
            ecdsaSecp384r1Sha384().id(),
            ecdsaSecp521r1Sha512().id(),
            TlsSignatureScheme.ed25519().id(),
            TlsSignatureScheme.ed448().id(),
            TlsSignatureScheme.rsaPssPssSha256().id(),
            TlsSignatureScheme.rsaPssPssSha384().id(),
            TlsSignatureScheme.rsaPssPssSha512().id(),
            TlsSignatureScheme.rsaPssRsaeSha256().id(),
            TlsSignatureScheme.rsaPssRsaeSha384().id(),
            TlsSignatureScheme.rsaPssRsaeSha512().id(),
            rsaPkcs1Sha256().id(),
            rsaPkcs1Sha384().id(),
            rsaPkcs1Sha512().id(),
            TlsSignatureAlgorithm.of(ecdsa(), sha224()).id(),
            TlsSignatureAlgorithm.of(rsa(), sha224()).id(),
            TlsSignatureAlgorithm.of(dsa(), sha224()).id(),
            TlsSignatureAlgorithm.of(dsa(), sha256()).id(),
            TlsSignatureAlgorithm.of(dsa(), sha384()).id(),
            TlsSignatureAlgorithm.of(dsa(), sha512()).id()
    ));

    public static SignatureAlgorithmsExtension of(List<TlsSignature> signatures) {
        return new SignatureAlgorithmsExtension(signatures.stream()
                .map(TlsSignature::id)
                .toList());
    }

    public static SignatureAlgorithmsExtension recommended() {
        return RECOMMENDED;
    }

    @Override
    public void serializeExtensionPayload(ByteBuffer buffer) {
        var size = algorithms.size() * INT16_LENGTH;
        writeLittleEndianInt16(buffer, size);
        for (var ecPointFormat : algorithms) {
            writeLittleEndianInt16(buffer, ecPointFormat);
        }
    }

    @Override
    public int extensionPayloadLength() {
        return INT16_LENGTH + INT16_LENGTH * algorithms.size();
    }

    @Override
    public int extensionType() {
        return SIGNATURE_ALGORITHMS_TYPE;
    }

    @Override
    public List<TlsVersion> versions() {
        return SIGNATURE_ALGORITHMS_VERSIONS;
    }

    @Override
    public TlsExtensionDecoder decoder() {
        return DECODER;
    }
}
