package it.auties.leap.tls.extension.implementation.signatureAlgorithms;

import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.extension.TlsConfiguredClientExtension;
import it.auties.leap.tls.extension.TlsConfiguredServerExtension;
import it.auties.leap.tls.extension.TlsExtensionDependencies;
import it.auties.leap.tls.extension.TlsExtensionDeserializer;
import it.auties.leap.tls.property.TlsProperty;
import it.auties.leap.tls.signature.TlsSignature;
import it.auties.leap.tls.signature.TlsSignatureAlgorithm;
import it.auties.leap.tls.signature.TlsSignatureAlgorithm.Hash;
import it.auties.leap.tls.signature.TlsSignatureAlgorithm.Signature;
import it.auties.leap.tls.signature.TlsSignatureScheme;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;
import java.util.List;

import static it.auties.leap.tls.util.BufferUtils.INT16_LENGTH;
import static it.auties.leap.tls.util.BufferUtils.writeBigEndianInt16;

public record SignatureAlgorithmsExtension(
        List<TlsSignature> algorithms
) implements TlsConfiguredClientExtension, TlsConfiguredServerExtension {
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
    public int extensionType() {
        return SIGNATURE_ALGORITHMS_TYPE;
    }

    @Override
    public List<TlsVersion> versions() {
        return SIGNATURE_ALGORITHMS_VERSIONS;
    }

    @Override
    public TlsExtensionDeserializer deserializer() {
        return SignatureAlgorithmsExtensionDeserializer.INSTANCE;
    }

    @Override
    public TlsExtensionDependencies dependencies() {
        return TlsExtensionDependencies.none();
    }
}
