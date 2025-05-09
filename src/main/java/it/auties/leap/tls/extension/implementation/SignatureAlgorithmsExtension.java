package it.auties.leap.tls.extension.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
import it.auties.leap.tls.connection.TlsConnectionType;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsContextualProperty;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.extension.TlsExtensionDependencies;
import it.auties.leap.tls.extension.TlsExtensionPayload;
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
) implements TlsExtension.Agnostic, TlsExtensionPayload {
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
    public TlsExtensionPayload toPayload(TlsContext context) {
        return this;
    }

    @Override
    public void apply(TlsContext context, TlsSource source) {
        var connection = switch (source) {
            case LOCAL -> context.localConnectionState();
            case REMOTE -> context.remoteConnectionState()
                    .orElseThrow(() -> new TlsAlert("No remote connection state was created", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR));
        };
        switch (connection.type()) {
            case CLIENT -> context.addAdvertisedValue(TlsContextualProperty.signatureAlgorithms(), algorithms);
            case SERVER -> context.addNegotiatedValue(TlsContextualProperty.signatureAlgorithms(), algorithms);
        }
    }

    @Override
    public Optional<SignatureAlgorithmsExtension> deserializeClient(TlsContext context, int type, ByteBuffer source) {
        return deserialize(context, source);
    }

    @Override
    public Optional<SignatureAlgorithmsExtension> deserializeServer(TlsContext context, int type, ByteBuffer source) {
        return deserialize(context, source);
    }

    private Optional<SignatureAlgorithmsExtension> deserialize(TlsContext context, ByteBuffer source) {
        var algorithmsSize = readBigEndianInt16(source);
        var algorithms = new ArrayList<TlsSignature>(algorithmsSize);
        var knownAlgorithms = context.getAdvertisedValue(TlsContextualProperty.signatureAlgorithms())
                .orElseThrow(() -> new TlsAlert("Missing negotiable property: signatureAlgorithms", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR))
                .stream()
                .collect(Collectors.toUnmodifiableMap(TlsSignature::id, Function.identity()));
        var mode = context.localConnectionState().type();
        for (var i = 0; i < algorithmsSize; i++) {
            var algorithmId = readBigEndianInt16(source);
            var algorithm = knownAlgorithms.get(algorithmId);
            if(algorithm != null) {
                algorithms.add(algorithm);
            }else if(mode == TlsConnectionType.CLIENT) {
                throw new TlsAlert("Remote tried to negotiate a signature algorithm that wasn't advertised", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
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
