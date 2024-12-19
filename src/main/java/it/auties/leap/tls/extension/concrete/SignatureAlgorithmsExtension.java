package it.auties.leap.tls.extension.concrete;

import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.config.TlsVersion;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static it.auties.leap.tls.BufferHelper.*;
import static it.auties.leap.tls.key.TlsSignatureAndHashAlgorithm.SignatureAlgorithm.Hash.sha224;
import static it.auties.leap.tls.key.TlsSignatureAndHashAlgorithm.SignatureAlgorithm.Hash.sha256;
import static it.auties.leap.tls.key.TlsSignatureAndHashAlgorithm.SignatureAlgorithm.Hash.sha384;
import static it.auties.leap.tls.key.TlsSignatureAndHashAlgorithm.SignatureAlgorithm.Hash.sha512;

import static it.auties.leap.tls.key.TlsSignatureAndHashAlgorithm.*;
import static it.auties.leap.tls.key.TlsSignatureAndHashAlgorithm.SignatureAlgorithm.Signature.ecdsa;
import static it.auties.leap.tls.key.TlsSignatureAndHashAlgorithm.SignatureAlgorithm.Signature.rsa;
import static it.auties.leap.tls.key.TlsSignatureAndHashAlgorithm.SignatureAlgorithm.Signature.dsa;

public record SignatureAlgorithmsExtension(List<Integer> algorithms) implements TlsExtension.Concrete {
    public static final SignatureAlgorithmsExtension RECOMMENDED = new SignatureAlgorithmsExtension(List.of(
            ecdsaSecp256r1Sha256().id(),
            ecdsaSecp384r1Sha384().id(),
            ecdsaSecp521r1Sha512().id(),
            ed25519().id(),
            ed448().id(),
            rsaPssPssSha256().id(),
            rsaPssPssSha384().id(),
            rsaPssPssSha512().id(),
            rsaPssRsaeSha256().id(),
            rsaPssRsaeSha384().id(),
            rsaPssRsaeSha512().id(),
            rsaPkcs1Sha256().id(),
            rsaPkcs1Sha384().id(),
            rsaPkcs1Sha512().id(),
            signatureAndHash(ecdsa(), sha224()).id(),
            signatureAndHash(rsa(), sha224()).id(),
            signatureAndHash(dsa(), sha224()).id(),
            signatureAndHash(dsa(), sha256()).id(),
            signatureAndHash(dsa(), sha384()).id(),
            signatureAndHash(dsa(), sha512()).id()
    ));
    public static final int EXTENSION_TYPE = 0x000D;

    public static Optional<SignatureAlgorithmsExtension> of(TlsVersion version, ByteBuffer buffer, int extensionLength) {
        var algorithmsSize = readLittleEndianInt16(buffer);
        var algorithms = new ArrayList<Integer>(algorithmsSize);
        for(var i = 0; i < algorithmsSize; i++) {
            var algorithmId = readLittleEndianInt16(buffer);
            algorithms.add(algorithmId);
        }
        var extension = new SignatureAlgorithmsExtension(algorithms);
        return Optional.of(extension);
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
        return EXTENSION_TYPE;
    }

    @Override
    public List<TlsVersion> versions() {
        return List.of(TlsVersion.TLS12, TlsVersion.TLS13);
    }
}
