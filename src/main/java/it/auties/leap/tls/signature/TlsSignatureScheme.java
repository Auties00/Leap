package it.auties.leap.tls.signature;

import java.util.Objects;

public final class TlsSignatureScheme implements TlsSignatureAndHashAlgorithm {
    private static final TlsSignatureAndHashAlgorithm ECDSA_SECP_256_R1_SHA256 = new TlsSignatureScheme(0x0403);
    private static final TlsSignatureAndHashAlgorithm ECDSA_SECP_384_R1_SHA384 = new TlsSignatureScheme(0x0503);
    private static final TlsSignatureAndHashAlgorithm ECDSA_SECP_521_R1_SHA512 = new TlsSignatureScheme(0x0603);
    private static final TlsSignatureAndHashAlgorithm ECDSA_SHA224 = new TlsSignatureScheme(0x0303);
    private static final TlsSignatureAndHashAlgorithm ECDSA_SHA1 = new TlsSignatureScheme(0x0203);
    private static final TlsSignatureAndHashAlgorithm RSA_PSS_RSAE_SHA256 = new TlsSignatureScheme(0x0408);
    private static final TlsSignatureAndHashAlgorithm RSA_PSS_RSAE_SHA384 = new TlsSignatureScheme(0x0805);
    private static final TlsSignatureAndHashAlgorithm RSA_PSS_RSAE_SHA512 = new TlsSignatureScheme(0x0806);
    private static final TlsSignatureAndHashAlgorithm ED25519 = new TlsSignatureScheme(0x0807);
    private static final TlsSignatureAndHashAlgorithm ED448 = new TlsSignatureScheme(0x0808);
    private static final TlsSignatureAndHashAlgorithm RSA_PSS_PSS_SHA256 = new TlsSignatureScheme(0x0809);
    private static final TlsSignatureAndHashAlgorithm RSA_PSS_PSS_SHA384 = new TlsSignatureScheme(0x080a);
    private static final TlsSignatureAndHashAlgorithm RSA_PSS_PSS_SHA512 = new TlsSignatureScheme(0x080b);
    private static final TlsSignatureAndHashAlgorithm RSA_PKCS_1_SHA256 = new TlsSignatureScheme(0x0401);
    private static final TlsSignatureAndHashAlgorithm RSA_PKCS_1_SHA384 = new TlsSignatureScheme(0x0501);
    private static final TlsSignatureAndHashAlgorithm RSA_PKCS_1_SHA512 = new TlsSignatureScheme(0x0601);
    private static final TlsSignatureAndHashAlgorithm RSA_PKCS_1_SHA224 = new TlsSignatureScheme(0x0301);
    private static final TlsSignatureAndHashAlgorithm RSA_PKCS_1_SHA1 = new TlsSignatureScheme(0x0201);
    private static final TlsSignatureAndHashAlgorithm DSA_SHA256 = new TlsSignatureScheme(0x0402);
    private static final TlsSignatureAndHashAlgorithm DSA_SHA384 = new TlsSignatureScheme(0x0502);
    private static final TlsSignatureAndHashAlgorithm DSA_SHA512 = new TlsSignatureScheme(0x0602);
    private static final TlsSignatureAndHashAlgorithm DSA_SHA224 = new TlsSignatureScheme(0x0302);
    private static final TlsSignatureAndHashAlgorithm DSA_SHA1 = new TlsSignatureScheme(0x0202);
    private static final TlsSignatureAndHashAlgorithm GOSTR_34102012_256Intrinsic = new TlsSignatureScheme(0x0840);
    private static final TlsSignatureAndHashAlgorithm GOSTR_34102012_512Intrinsic = new TlsSignatureScheme(0x0841);
    private static final TlsSignatureAndHashAlgorithm GOSTR_34102012_256_GOSTR_34112012_256 = new TlsSignatureScheme(0xeeee);
    private static final TlsSignatureAndHashAlgorithm GOSTR_34102012_512_GOSTR_34112012_512 = new TlsSignatureScheme(0xefef);
    private static final TlsSignatureAndHashAlgorithm GOSTR_34102001_GOSTR_3411 = new TlsSignatureScheme(0xeded);

    public static TlsSignatureAndHashAlgorithm ecdsaSecp256r1Sha256() {
        return TlsSignatureScheme.ECDSA_SECP_256_R1_SHA256;
    }

    public static TlsSignatureAndHashAlgorithm ecdsaSecp384r1Sha384() {
        return TlsSignatureScheme.ECDSA_SECP_384_R1_SHA384;
    }

    public static TlsSignatureAndHashAlgorithm ecdsaSecp521r1Sha512() {
        return TlsSignatureScheme.ECDSA_SECP_521_R1_SHA512;
    }

    public static TlsSignatureAndHashAlgorithm ecdsaSha224() {
        return TlsSignatureScheme.ECDSA_SHA224;
    }

    public static TlsSignatureAndHashAlgorithm ecdsaSha1() {
        return TlsSignatureScheme.ECDSA_SHA1;
    }

    public static TlsSignatureAndHashAlgorithm rsaPssRsaeSha256() {
        return TlsSignatureScheme.RSA_PSS_RSAE_SHA256;
    }

    public static TlsSignatureAndHashAlgorithm rsaPssRsaeSha384() {
        return TlsSignatureScheme.RSA_PSS_RSAE_SHA384;
    }

    public static TlsSignatureAndHashAlgorithm rsaPssRsaeSha512() {
        return TlsSignatureScheme.RSA_PSS_RSAE_SHA512;
    }

    public static TlsSignatureAndHashAlgorithm ed25519() {
        return TlsSignatureScheme.ED25519;
    }

    public static TlsSignatureAndHashAlgorithm ed448() {
        return TlsSignatureScheme.ED448;
    }

    public static TlsSignatureAndHashAlgorithm rsaPssPssSha256() {
        return TlsSignatureScheme.RSA_PSS_PSS_SHA256;
    }

    public static TlsSignatureAndHashAlgorithm rsaPssPssSha384() {
        return TlsSignatureScheme.RSA_PSS_PSS_SHA384;
    }

    public static TlsSignatureAndHashAlgorithm rsaPssPssSha512() {
        return TlsSignatureScheme.RSA_PSS_PSS_SHA512;
    }

    public static TlsSignatureAndHashAlgorithm rsaPkcs1Sha256() {
        return TlsSignatureScheme.RSA_PKCS_1_SHA256;
    }

    public static TlsSignatureAndHashAlgorithm rsaPkcs1Sha384() {
        return TlsSignatureScheme.RSA_PKCS_1_SHA384;
    }

    public static TlsSignatureAndHashAlgorithm rsaPkcs1Sha512() {
        return TlsSignatureScheme.RSA_PKCS_1_SHA512;
    }

    public static TlsSignatureAndHashAlgorithm rsaPkcs1Sha224() {
        return TlsSignatureScheme.RSA_PKCS_1_SHA224;
    }

    public static TlsSignatureAndHashAlgorithm rsaPkcs1Sha1() {
        return TlsSignatureScheme.RSA_PKCS_1_SHA1;
    }

    public static TlsSignatureAndHashAlgorithm dsaSha256() {
        return TlsSignatureScheme.DSA_SHA256;
    }

    public static TlsSignatureAndHashAlgorithm dsaSha384() {
        return TlsSignatureScheme.DSA_SHA384;
    }

    public static TlsSignatureAndHashAlgorithm dsaSha512() {
        return TlsSignatureScheme.DSA_SHA512;
    }

    public static TlsSignatureAndHashAlgorithm dsaSha224() {
        return TlsSignatureScheme.DSA_SHA224;
    }

    public static TlsSignatureAndHashAlgorithm dsaSha1() {
        return TlsSignatureScheme.DSA_SHA1;
    }

    public static TlsSignatureAndHashAlgorithm gostr256Intrinsic() {
        return TlsSignatureScheme.GOSTR_34102012_256Intrinsic;
    }

    public static TlsSignatureAndHashAlgorithm gostr512Intrinsic() {
        return TlsSignatureScheme.GOSTR_34102012_512Intrinsic;
    }

    public static TlsSignatureAndHashAlgorithm gostr256Gostr256() {
        return TlsSignatureScheme.GOSTR_34102012_256_GOSTR_34112012_256;
    }

    public static TlsSignatureAndHashAlgorithm gostr512Gostr512() {
        return TlsSignatureScheme.GOSTR_34102012_512_GOSTR_34112012_512;
    }

    public static TlsSignatureAndHashAlgorithm gostr34102001Gostr3411() {
        return TlsSignatureScheme.GOSTR_34102001_GOSTR_3411;
    }

    public static TlsSignatureAndHashAlgorithm reservedForPrivateUse(int id) {
        return new TlsSignatureScheme(id);
    }

    private final int id;
    private TlsSignatureScheme(int id) {
        this.id = id;
    }

    @Override
    public int id() {
        return id;
    }

    @Override
    public boolean equals(Object other) {
        return other == this || other instanceof TlsSignatureScheme that
                && Objects.equals(this.id(), that.id());
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }
}
