package it.auties.leap.tls.extension.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsContextMode;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.extension.TlsExtensionDependencies;
import it.auties.leap.tls.property.TlsIdentifiableProperty;
import it.auties.leap.tls.property.TlsProperty;
import it.auties.leap.tls.signature.TlsSignature;
import it.auties.leap.tls.signature.TlsSignatureAlgorithm;
import it.auties.leap.tls.signature.TlsSignatureAlgorithm.Hash;
import it.auties.leap.tls.signature.TlsSignatureAlgorithm.Signature;
import it.auties.leap.tls.signature.TlsSignatureScheme;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;

import static it.auties.leap.tls.util.BufferUtils.*;

public record SignatureAlgorithmsExtension(
        List<TlsSignature> algorithms
) implements TlsExtension.Configured.Agnostic {
    private static final SignatureAlgorithmsExtension RECOMMENDED = new SignatureAlgorithmsExtension(List.of(
            TlsSignatureScheme.ecdsaSecp256r1Sha256(),
            TlsSignatureScheme.ecdsaSecp384r1Sha384(),
            TlsSignatureScheme.ecdsaSecp521r1Sha512(),
            TlsSignatureScheme.ed25519(),
            TlsSignatureScheme.ed448(),
            TlsSignatureScheme.rsaPssPssSha256(),
            TlsSignatureScheme.rsaPssPssSha384(),
            TlsSignatureScheme.rsaPssPssSha512(),
            TlsSignatureScheme.rsaPssRsaeSha256(),
            TlsSignatureScheme.rsaPssRsaeSha384(),
            TlsSignatureScheme.rsaPssRsaeSha512(),
            TlsSignatureScheme.rsaPkcs1Sha256(),
            TlsSignatureScheme.rsaPkcs1Sha384(),
            TlsSignatureScheme.rsaPkcs1Sha512(),
            TlsSignatureAlgorithm.of(Signature.ecdsa(), Hash.sha224()),
            TlsSignatureAlgorithm.of(Signature.rsa(), Hash.sha224()),
            TlsSignatureAlgorithm.of(Signature.dsa(), Hash.sha224()),
            TlsSignatureAlgorithm.of(Signature.dsa(), Hash.sha256()),
            TlsSignatureAlgorithm.of(Signature.dsa(), Hash.sha384()),
            TlsSignatureAlgorithm.of(Signature.dsa(), Hash.sha512())
    ));

    public static SignatureAlgorithmsExtension recommended() {
        return RECOMMENDED;
    }

    @Override
    public void serializePayload(ByteBuffer buffer) {
        writeBigEndianInt16(buffer, algorithms.size() * INT16_LENGTH);
        for (var ecPointFormat : algorithms) {
            writeBigEndianInt16(buffer, ecPointFormat.id());
        }
    }

    @Override
    public int payloadLength() {
        return INT16_LENGTH + INT16_LENGTH * algorithms.size();
    }

    @Override
    public void apply(TlsContext context, TlsSource source) {
        switch (source) {
            case LOCAL -> context.addNegotiableProperty(TlsProperty.signatureAlgorithms(), algorithms);
            case REMOTE -> context.addNegotiatedProperty(TlsProperty.signatureAlgorithms(), algorithms);
        }
    }

    @Override
    public Optional<SignatureAlgorithmsExtension> deserialize(TlsContext context, int type, ByteBuffer buffer) {
        var algorithmsSize = readBigEndianInt16(buffer);
        var algorithms = new ArrayList<TlsSignature>(algorithmsSize);
        var knownAlgorithms = context.getNegotiableValue(TlsProperty.signatureAlgorithms())
                .orElseThrow(() -> TlsAlert.noNegotiableProperty(TlsProperty.signatureAlgorithms()))
                .stream()
                .collect(Collectors.toUnmodifiableMap(TlsIdentifiableProperty::id, Function.identity()));
        var mode = context.selectedMode();
        for (var i = 0; i < algorithmsSize; i++) {
            var algorithmId = readBigEndianInt16(buffer);
            var algorithm = knownAlgorithms.get(algorithmId);
            if(algorithm != null) {
                algorithms.add(algorithm);
            }else if(mode == TlsContextMode.CLIENT) {
                throw new TlsAlert("Remote tried to negotiate a signature algorithm that wasn't advertised");
            }
        }
        var extension = new SignatureAlgorithmsExtension(algorithms);
        return Optional.of(extension);
    }

    @Override
    public int type() {
        return SIGNATURE_ALGORITHMS_TYPE;
    }

    @Override
    public List<TlsVersion> versions() {
        return SIGNATURE_ALGORITHMS_VERSIONS;
    }

    @Override
    public TlsExtensionDependencies dependencies() {
        return TlsExtensionDependencies.none();
    }
}
