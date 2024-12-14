package it.auties.leap.tls.extension.concrete;

import it.auties.leap.tls.TlsSignatureAlgorithm;
import it.auties.leap.tls.TlsVersion;
import it.auties.leap.tls.extension.TlsConcreteExtension;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static it.auties.leap.tls.TlsBuffer.*;

public final class SignatureAlgorithmsExtension extends TlsConcreteExtension {
    public static final SignatureAlgorithmsExtension RECOMMENDED = new SignatureAlgorithmsExtension(List.of(
            TlsSignatureAlgorithm.ecdsaSecp256r1Sha256(),
            TlsSignatureAlgorithm.ecdsaSecp384r1Sha384(),
            TlsSignatureAlgorithm.ecdsaSecp521r1Sha512(),
            TlsSignatureAlgorithm.ed25519(),
            TlsSignatureAlgorithm.ed448(),
            TlsSignatureAlgorithm.rsaPssPssSha256(),
            TlsSignatureAlgorithm.rsaPssPssSha384(),
            TlsSignatureAlgorithm.rsaPssPssSha512(),
            TlsSignatureAlgorithm.rsaPssRsaeSha256(),
            TlsSignatureAlgorithm.rsaPssRsaeSha384(),
            TlsSignatureAlgorithm.rsaPssRsaeSha512(),
            TlsSignatureAlgorithm.rsaPkcs1Sha256(),
            TlsSignatureAlgorithm.rsaPkcs1Sha384(),
            TlsSignatureAlgorithm.rsaPkcs1Sha512(),
            TlsSignatureAlgorithm.ofTlsV12(TlsSignatureAlgorithm.Signature.ECDSA, TlsSignatureAlgorithm.Hash.SHA224),
            TlsSignatureAlgorithm.ofTlsV12(TlsSignatureAlgorithm.Signature.RSA, TlsSignatureAlgorithm.Hash.SHA224),
            TlsSignatureAlgorithm.ofTlsV12(TlsSignatureAlgorithm.Signature.DSA, TlsSignatureAlgorithm.Hash.SHA224),
            TlsSignatureAlgorithm.ofTlsV12(TlsSignatureAlgorithm.Signature.DSA, TlsSignatureAlgorithm.Hash.SHA256),
            TlsSignatureAlgorithm.ofTlsV12(TlsSignatureAlgorithm.Signature.DSA, TlsSignatureAlgorithm.Hash.SHA384),
            TlsSignatureAlgorithm.ofTlsV12(TlsSignatureAlgorithm.Signature.DSA, TlsSignatureAlgorithm.Hash.SHA512)
    ));
    public static final int EXTENSION_TYPE = 0x000D;

    private final List<TlsSignatureAlgorithm> algorithms;

    public SignatureAlgorithmsExtension(List<TlsSignatureAlgorithm> algorithms) {
        this.algorithms = algorithms;
    }

    public static Optional<SignatureAlgorithmsExtension> of(TlsVersion version, ByteBuffer buffer, int extensionLength) {
        var algorithmsSize = readLittleEndianInt16(buffer);
        var algorithms = new ArrayList<TlsSignatureAlgorithm>(algorithmsSize);
        for(var i = 0; i < algorithmsSize; i++) {
            var algorithmId = readLittleEndianInt16(buffer);
            var algorithm = switch (version) {
                case TLS13, DTLS13 -> TlsSignatureAlgorithm.ofTlsV13(algorithmId);
                case TLS12, DTLS12 -> TlsSignatureAlgorithm.ofTlsV12(algorithmId)
                        .orElseThrow(() -> new IllegalArgumentException("Unknown tls algorithm: " + algorithmId));
                default -> throw new IllegalArgumentException("Unsupported TLS version: " + version);
            };
            algorithms.add(algorithm);
        }
        var extension = new SignatureAlgorithmsExtension(algorithms);
        return Optional.of(extension);
    }

    @Override
    protected void serializeExtensionPayload(ByteBuffer buffer) {
        var size = algorithms.size() * INT16_LENGTH;
        writeLittleEndianInt16(buffer, size);
        for (var ecPointFormat : algorithms) {
            writeLittleEndianInt16(buffer, ecPointFormat.id());
        }
    }

    @Override
    public int extensionPayloadLength() {
        return INT16_LENGTH + INT16_LENGTH * algorithms.size();
    }

    @Override
    public int extensionType() {
        return EXTENSION_TYPE;
    }

    @Override
    public List<TlsVersion> versions() {
        return List.of(TlsVersion.TLS12, TlsVersion.TLS13);
    }
}
