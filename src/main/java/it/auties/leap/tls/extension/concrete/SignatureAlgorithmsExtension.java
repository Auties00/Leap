package it.auties.leap.tls.extension.concrete;

import it.auties.leap.tls.config.TlsIdentifiableUnion;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.key.TlsSignatureAndHashAlgorithm;
import it.auties.leap.tls.config.TlsVersion;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static it.auties.leap.tls.BufferHelper.*;
import static it.auties.leap.tls.key.TlsSignatureAndHashAlgorithm.SignatureAndHash.Signature.ecdsa;
import static it.auties.leap.tls.key.TlsSignatureAndHashAlgorithm.SignatureAndHash.Signature.rsa;
import static it.auties.leap.tls.key.TlsSignatureAndHashAlgorithm.SignatureAndHash.Signature.dsa;

public final class SignatureAlgorithmsExtension extends TlsExtension.Concrete {
    public static final SignatureAlgorithmsExtension RECOMMENDED = new SignatureAlgorithmsExtension(List.of(
            TlsIdentifiableUnion.of(ecdsaSecp256r1Sha256()),
            TlsIdentifiableUnion.of(ecdsaSecp384r1Sha384()),
            TlsIdentifiableUnion.of(ecdsaSecp521r1Sha512()),
            TlsIdentifiableUnion.of(ed25519()),
            TlsIdentifiableUnion.of(ed448()),
            TlsIdentifiableUnion.of(rsaPssPssSha256()),
            TlsIdentifiableUnion.of(rsaPssPssSha384()),
            TlsIdentifiableUnion.of(rsaPssPssSha512()),
            TlsIdentifiableUnion.of(rsaPssRsaeSha256()),
            TlsIdentifiableUnion.of(rsaPssRsaeSha384()),
            TlsIdentifiableUnion.of(rsaPssRsaeSha512()),
            TlsIdentifiableUnion.of(rsaPkcs1Sha256()),
            TlsIdentifiableUnion.of(rsaPkcs1Sha384()),
            TlsIdentifiableUnion.of(rsaPkcs1Sha512()),
            TlsIdentifiableUnion.of(signatureAndHash(ecdsa(), sha224())),
            TlsIdentifiableUnion.of(signatureAndHash(rsa(), sha224())),
            TlsIdentifiableUnion.of(signatureAndHash(dsa(), sha224())),
            TlsIdentifiableUnion.of(signatureAndHash(dsa(), sha256())),
            TlsIdentifiableUnion.of(signatureAndHash(dsa(), sha384())),
            TlsIdentifiableUnion.of(signatureAndHash(dsa(), sha512()))
    ));
    public static final int EXTENSION_TYPE = 0x000D;

    private final List<? extends TlsIdentifiableUnion<TlsSignatureAndHashAlgorithm, Integer>> algorithms;

    public SignatureAlgorithmsExtension(List<? extends TlsIdentifiableUnion<TlsSignatureAndHashAlgorithm, Integer>> algorithms) {
        this.algorithms = algorithms;
    }

    public static Optional<SignatureAlgorithmsExtension> of(TlsVersion version, ByteBuffer buffer, int extensionLength) {
        var algorithmsSize = readLittleEndianInt16(buffer);
        var algorithms = new ArrayList<TlsIdentifiableUnion<TlsSignatureAndHashAlgorithm, Integer>>(algorithmsSize);
        for(var i = 0; i < algorithmsSize; i++) {
            var algorithmId = readLittleEndianInt16(buffer);
            algorithms.add(TlsIdentifiableUnion.of(algorithmId));
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
