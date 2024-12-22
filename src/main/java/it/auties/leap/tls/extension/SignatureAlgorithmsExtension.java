package it.auties.leap.tls.extension;

import it.auties.leap.tls.config.TlsVersion;
import it.auties.leap.tls.signature.TlsSignatureAlgorithm;
import it.auties.leap.tls.signature.TlsSignatureScheme;

import java.nio.ByteBuffer;
import java.util.List;

import static it.auties.leap.tls.signature.TlsSignatureAlgorithm.Hash.*;
import static it.auties.leap.tls.signature.TlsSignatureAlgorithm.Signature.*;
import static it.auties.leap.tls.signature.TlsSignatureScheme.*;
import static it.auties.leap.tls.util.BufferHelper.INT16_LENGTH;
import static it.auties.leap.tls.util.BufferHelper.writeLittleEndianInt16;

public final class SignatureAlgorithmsExtension implements TlsExtension.Implementation {
    static final SignatureAlgorithmsExtension RECOMMENDED = new SignatureAlgorithmsExtension(List.of(
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

    private final List<Integer> algorithms;
    SignatureAlgorithmsExtension(List<Integer> algorithms) {
        this.algorithms = algorithms;
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
        return TlsExtensions.SIGNATURE_ALGORITHMS_TYPE;
    }

    @Override
    public List<TlsVersion> versions() {
        return TlsExtensions.SIGNATURE_ALGORITHMS_VERSIONS;
    }

    public List<Integer> algorithms() {
        return algorithms;
    }

}
