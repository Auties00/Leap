package it.auties.leap.tls.signature;

import it.auties.leap.tls.exception.TlsException;

import java.net.URI;
import java.util.Objects;

// https://www.iana.org/assignments/tls-parameters/tls-signaturescheme.csv
public final class TlsSignatureScheme implements TlsSignature {
    private static final TlsSignature RSA_PKCS1_SHA1 = new TlsSignatureScheme(0x0201, false);
    private static final TlsSignature ECDSA_SHA1 = new TlsSignatureScheme(0x0203, false);
    private static final TlsSignature RSA_PKCS1_SHA256 = new TlsSignatureScheme(0x0401, true);
    private static final TlsSignature ECDSA_SECP256R1_SHA256 = new TlsSignatureScheme(0x0403, true);
    private static final TlsSignature RSA_PKCS1_SHA256_LEGACY = new TlsSignatureScheme(0x0420, false);
    private static final TlsSignature RSA_PKCS1_SHA384 = new TlsSignatureScheme(0x0501, true);
    private static final TlsSignature ECDSA_SECP384R1_SHA384 = new TlsSignatureScheme(0x0503, true);
    private static final TlsSignature RSA_PKCS1_SHA384_LEGACY = new TlsSignatureScheme(0x0520, false);
    private static final TlsSignature RSA_PKCS1_SHA512 = new TlsSignatureScheme(0x0601, true);
    private static final TlsSignature ECDSA_SECP521R1_SHA512 = new TlsSignatureScheme(0x0603, true);
    private static final TlsSignature RSA_PKCS1_SHA512_LEGACY = new TlsSignatureScheme(0x0620, false);
    private static final TlsSignature ECCSI_SHA256 = new TlsSignatureScheme(0x0704, false);
    private static final TlsSignature ISO_IBS1 = new TlsSignatureScheme(0x0705, false);
    private static final TlsSignature ISO_IBS2 = new TlsSignatureScheme(0x0706, false);
    private static final TlsSignature ISO_CHINESE_IBS = new TlsSignatureScheme(0x0707, false);
    private static final TlsSignature SM2SIG_SM3 = new TlsSignatureScheme(0x0708, false);
    private static final TlsSignature GOSTR34102012_256A = new TlsSignatureScheme(0x0709, false);
    private static final TlsSignature GOSTR34102012_256B = new TlsSignatureScheme(0x070A, false);
    private static final TlsSignature GOSTR34102012_256C = new TlsSignatureScheme(0x070B, false);
    private static final TlsSignature GOSTR34102012_256D = new TlsSignatureScheme(0x070C, false);
    private static final TlsSignature GOSTR34102012_512A = new TlsSignatureScheme(0x070D, false);
    private static final TlsSignature GOSTR34102012_512B = new TlsSignatureScheme(0x070E, false);
    private static final TlsSignature GOSTR34102012_512C = new TlsSignatureScheme(0x070F, false);
    private static final TlsSignature RSA_PSS_RSAE_SHA256 = new TlsSignatureScheme(0x0804, true);
    private static final TlsSignature RSA_PSS_RSAE_SHA384 = new TlsSignatureScheme(0x0805, true);
    private static final TlsSignature RSA_PSS_RSAE_SHA512 = new TlsSignatureScheme(0x0806, true);
    private static final TlsSignature ED25519 = new TlsSignatureScheme(0x0807, true);
    private static final TlsSignature ED448 = new TlsSignatureScheme(0x0808, true);
    private static final TlsSignature RSA_PSS_PSS_SHA256 = new TlsSignatureScheme(0x0809, true);
    private static final TlsSignature RSA_PSS_PSS_SHA384 = new TlsSignatureScheme(0x080A, true);
    private static final TlsSignature RSA_PSS_PSS_SHA512 = new TlsSignatureScheme(0x080B, true);
    private static final TlsSignature ECDSA_BRAINPOOLP256R1TLS13_SHA256 = new TlsSignatureScheme(0x081A, false);
    private static final TlsSignature ECDSA_BRAINPOOLP384R1TLS13_SHA384 = new TlsSignatureScheme(0x081B, false);
    private static final TlsSignature ECDSA_BRAINPOOLP512R1TLS13_SHA512 = new TlsSignatureScheme(0x081C, false);

    public static TlsSignature rsaPkcs1Sha1() {
        return RSA_PKCS1_SHA1;
    }

    public static TlsSignature ecdsaSha1() {
        return ECDSA_SHA1;
    }

    public static TlsSignature rsaPkcs1Sha256() {
        return RSA_PKCS1_SHA256;
    }

    public static TlsSignature ecdsaSecp256r1Sha256() {
        return ECDSA_SECP256R1_SHA256;
    }

    public static TlsSignature rsaPkcs1Sha256Legacy() {
        return RSA_PKCS1_SHA256_LEGACY;
    }

    public static TlsSignature rsaPkcs1Sha384() {
        return RSA_PKCS1_SHA384;
    }

    public static TlsSignature ecdsaSecp384r1Sha384() {
        return ECDSA_SECP384R1_SHA384;
    }

    public static TlsSignature rsaPkcs1Sha384Legacy() {
        return RSA_PKCS1_SHA384_LEGACY;
    }

    public static TlsSignature rsaPkcs1Sha512() {
        return RSA_PKCS1_SHA512;
    }

    public static TlsSignature ecdsaSecp521r1Sha512() {
        return ECDSA_SECP521R1_SHA512;
    }

    public static TlsSignature rsaPkcs1Sha512Legacy() {
        return RSA_PKCS1_SHA512_LEGACY;
    }

    public static TlsSignature eccsiSha256() {
        return ECCSI_SHA256;
    }

    public static TlsSignature isoIbs1() {
        return ISO_IBS1;
    }

    public static TlsSignature isoIbs2() {
        return ISO_IBS2;
    }

    public static TlsSignature isoChineseIbs() {
        return ISO_CHINESE_IBS;
    }

    public static TlsSignature sm2sigSm3() {
        return SM2SIG_SM3;
    }

    public static TlsSignature gostr34102012_256a() {
        return GOSTR34102012_256A;
    }

    public static TlsSignature gostr34102012_256b() {
        return GOSTR34102012_256B;
    }

    public static TlsSignature gostr34102012_256c() {
        return GOSTR34102012_256C;
    }

    public static TlsSignature gostr34102012_256d() {
        return GOSTR34102012_256D;
    }

    public static TlsSignature gostr34102012_512a() {
        return GOSTR34102012_512A;
    }

    public static TlsSignature gostr34102012_512b() {
        return GOSTR34102012_512B;
    }

    public static TlsSignature gostr34102012_512c() {
        return GOSTR34102012_512C;
    }

    public static TlsSignature rsaPssRsaeSha256() {
        return RSA_PSS_RSAE_SHA256;
    }

    public static TlsSignature rsaPssRsaeSha384() {
        return RSA_PSS_RSAE_SHA384;
    }

    public static TlsSignature rsaPssRsaeSha512() {
        return RSA_PSS_RSAE_SHA512;
    }

    public static TlsSignature ed25519() {
        return ED25519;
    }

    public static TlsSignature ed448() {
        return ED448;
    }

    public static TlsSignature rsaPssPssSha256() {
        return RSA_PSS_PSS_SHA256;
    }

    public static TlsSignature rsaPssPssSha384() {
        return RSA_PSS_PSS_SHA384;
    }

    public static TlsSignature rsaPssPssSha512() {
        return RSA_PSS_PSS_SHA512;
    }

    public static TlsSignature ecdsaBrainpoolp256r1Tls13Sha256() {
        return ECDSA_BRAINPOOLP256R1TLS13_SHA256;
    }

    public static TlsSignature ecdsaBrainpoolp384r1Tls13Sha384() {
        return ECDSA_BRAINPOOLP384R1TLS13_SHA384;
    }

    public static TlsSignature ecdsaBrainpoolp512r1Tls13Sha512() {
        return ECDSA_BRAINPOOLP512R1TLS13_SHA512;
    }

    public static TlsSignature reservedForPrivateUse(int id) {
        if(id < 0xFE00 || id > 0xFFFF) {
            throw new TlsException(
                    "Only values from 0xFE00-0xFFFF (hex) inclusive are reserved for Private Use",
                    URI.create("https://www.iana.org/assignments/tls-parameters/tls-signaturescheme.csv")
            );
        }

        return new TlsSignatureScheme(id, false);
    }

    private final int id;
    private final boolean recommended;
    private TlsSignatureScheme(int id, boolean recommended) {
        this.id = id;
        this.recommended = recommended;
    }

    @Override
    public int id() {
        return id;
    }

    public boolean recommended() {
        return recommended;
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
