package it.auties.leap.tls;

import java.util.Arrays;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;

public sealed abstract class TlsSignatureAlgorithm {
    public abstract int id();

    public static Optional<TlsSignatureAlgorithm> ofTlsV12(int id) {
        var hash = Hash.of((byte) (id >> 8));
        if(hash.isEmpty()) {
            return Optional.empty();
        }

        var signature = Signature.of((byte) id);
        if(signature.isEmpty()) {
            return Optional.empty();
        }

        if((hash.get() == Hash.INTRINSIC) != signature.get().intrinsicHash()) {
            return Optional.empty();
        }

        var algorithm = new TlsV12Signature(signature.get(), hash.get());
        return Optional.of(algorithm);
    }

    public static TlsSignatureAlgorithm ofTlsV12(Signature signature, Hash hash) {
        return new TlsV12Signature(signature, hash);
    }

    public static TlsSignatureAlgorithm ofTlsV13(int id) {
        return new TlsV13Signature(id);
    }

    public static TlsSignatureAlgorithm ecdsaSecp256r1Sha256() {
        return TlsV13Signature.ECDSA_SECP_256_R_1_SHA_256;
    }

    public static TlsSignatureAlgorithm ecdsaSecp384r1Sha384() {
        return TlsV13Signature.ECDSA_SECP_384_R_1_SHA_384;
    }

    public static TlsSignatureAlgorithm ecdsaSecp521r1Sha512() {
        return TlsV13Signature.ECDSA_SECP_521_R_1_SHA_512;
    }

    public static TlsSignatureAlgorithm ecdsaSha224() {
        return TlsV13Signature.ECDSA_SHA_224;
    }

    public static TlsSignatureAlgorithm ecdsaSha1() {
        return TlsV13Signature.ECDSA_SHA_1;
    }

    public static TlsSignatureAlgorithm rsaPssRsaeSha256() {
        return TlsV13Signature.RSA_PSS_RSAE_SHA_256;
    }

    public static TlsSignatureAlgorithm rsaPssRsaeSha384() {
        return TlsV13Signature.RSA_PSS_RSAE_SHA_384;
    }

    public static TlsSignatureAlgorithm rsaPssRsaeSha512() {
        return TlsV13Signature.RSA_PSS_RSAE_SHA_512;
    }

    public static TlsSignatureAlgorithm ed25519() {
        return TlsV13Signature.ED25519;
    }

    public static TlsSignatureAlgorithm ed448() {
        return TlsV13Signature.ED448;
    }

    public static TlsSignatureAlgorithm rsaPssPssSha256() {
        return TlsV13Signature.RSA_PSS_PSS_SHA_256;
    }

    public static TlsSignatureAlgorithm rsaPssPssSha384() {
        return TlsV13Signature.RSA_PSS_PSS_SHA_384;
    }

    public static TlsSignatureAlgorithm rsaPssPssSha512() {
        return TlsV13Signature.RSA_PSS_PSS_SHA_512;
    }

    public static TlsSignatureAlgorithm rsaPkcs1Sha256() {
        return TlsV13Signature.RSA_PKCS_1_SHA_256;
    }

    public static TlsSignatureAlgorithm rsaPkcs1Sha384() {
        return TlsV13Signature.RSA_PKCS_1_SHA_384;
    }

    public static TlsSignatureAlgorithm rsaPkcs1Sha512() {
        return TlsV13Signature.RSA_PKCS_1_SHA_512;
    }

    public static TlsSignatureAlgorithm rsaPkcs1Sha224() {
        return TlsV13Signature.RSA_PKCS_1_SHA_224;
    }

    public static TlsSignatureAlgorithm rsaPkcs1Sha1() {
        return TlsV13Signature.RSA_PKCS_1_SHA_1;
    }

    public static TlsSignatureAlgorithm dsaSha256() {
        return TlsV13Signature.DSA_SHA_256;
    }

    public static TlsSignatureAlgorithm dsaSha384() {
        return TlsV13Signature.DSA_SHA_384;
    }

    public static TlsSignatureAlgorithm dsaSha512() {
        return TlsV13Signature.DSA_SHA_512;
    }

    public static TlsSignatureAlgorithm dsaSha224() {
        return TlsV13Signature.DSA_SHA_224;
    }

    public static TlsSignatureAlgorithm dsaSha1() {
        return TlsV13Signature.DSA_SHA_1;
    }

    public static TlsSignatureAlgorithm gostr34102012256Intrinsic() {
        return TlsV13Signature.GOSTR_34102012_256Intrinsic;
    }

    public static TlsSignatureAlgorithm gostr34102012512Intrinsic() {
        return TlsV13Signature.GOSTR_34102012_512Intrinsic;
    }

    public static TlsSignatureAlgorithm gostr34102012256Gostr34112012_256() {
        return TlsV13Signature.GOSTR_34102012_256_GOSTR_34112012_256;
    }

    public static TlsSignatureAlgorithm gostr34102012512Gostr34112012512() {
        return TlsV13Signature.GOSTR_34102012_512_GOSTR_34112012_512;
    }

    public static TlsSignatureAlgorithm gostr34102001Gostr3411() {
        return TlsV13Signature.GOSTR_34102001_GOSTR_3411;
    }

    public enum Signature {
        ANONYMOUS((byte) 0, false),
        RSA((byte) 1, false),
        DSA((byte) 2, false),
        ECDSA((byte) 3, false),
        RSA_PSS_RSAE_SHA_256((byte) 4, true),
        RSA_PSS_RSAE_SHA_384((byte) 5, true),
        RSA_PSS_RSAE_SHA_512((byte) 6, true),
        ED25519((byte) 7, true),
        ED448((byte) 8, true),
        RSA_PSS_PSS_SHA_256((byte) 9, true),
        RSA_PSS_PSS_SHA_384((byte) 10, true),
        RSA_PSS_PSS_SHA_512((byte) 11, true),
        GOSTR34102012_256((byte) 64, false),
        GOSTR34102012_512((byte) 65, false);

        private static final Map<Byte, Signature> VALUES = Arrays.stream(values())
                .collect(Collectors.toUnmodifiableMap(Signature::id, Function.identity()));

        private final byte id;
        private final boolean intrinsicHash;
        Signature(byte id, boolean intrinsicHash) {
            this.id = id;
            this.intrinsicHash = intrinsicHash;
        }

        public static Optional<Signature> of(byte id) {
            return Optional.ofNullable(VALUES.get(id));
        }

        public byte id() {
            return id;
        }

        public boolean intrinsicHash() {
            return intrinsicHash;
        }
    }

    public enum Hash {
        NONE((byte) 0),
        MD5((byte) 1),
        SHA1((byte) 2),
        SHA224((byte) 3),
        SHA256((byte) 4),
        SHA384((byte) 5),
        SHA512((byte) 6),
        INTRINSIC((byte) 8);

        private static final Map<Byte, Hash> VALUES = Arrays.stream(values())
                .collect(Collectors.toUnmodifiableMap(Hash::id, Function.identity()));

        private final byte id;

        Hash(byte id) {
            this.id = id;
        }

        public static Optional<Hash> of(byte id) {
            return Optional.ofNullable(VALUES.get(id));
        }

        public byte id() {
            return id;
        }
    }

    private static final class TlsV12Signature extends TlsSignatureAlgorithm {
        private final Signature signature;
        private final Hash hash;

        public TlsV12Signature(Signature signature, Hash hash) {
            this.hash = hash;
            this.signature = signature;
        }

        @Override
        public int id() {
            return (hash.id() << 8) | signature.id();
        }
    }

    private static final class TlsV13Signature extends TlsSignatureAlgorithm {
        public static final TlsSignatureAlgorithm ECDSA_SECP_256_R_1_SHA_256 = new TlsV13Signature(0x0403);
        public static final TlsSignatureAlgorithm ECDSA_SECP_384_R_1_SHA_384 = new TlsV13Signature(0x0503);
        public static final TlsSignatureAlgorithm ECDSA_SECP_521_R_1_SHA_512 = new TlsV13Signature(0x0603);
        public static final TlsSignatureAlgorithm ECDSA_SHA_224 = new TlsV13Signature(0x0303);
        public static final TlsSignatureAlgorithm ECDSA_SHA_1 = new TlsV13Signature(0x0203);
        public static final TlsSignatureAlgorithm RSA_PSS_RSAE_SHA_256 = new TlsV13Signature(0x0408);
        public static final TlsSignatureAlgorithm RSA_PSS_RSAE_SHA_384 = new TlsV13Signature(0x0805);
        public static final TlsSignatureAlgorithm RSA_PSS_RSAE_SHA_512 = new TlsV13Signature(0x0806);
        public static final TlsSignatureAlgorithm ED25519 = new TlsV13Signature(0x0807);
        public static final TlsSignatureAlgorithm ED448 = new TlsV13Signature(0x0808);
        public static final TlsSignatureAlgorithm RSA_PSS_PSS_SHA_256 = new TlsV13Signature(0x0809);
        public static final TlsSignatureAlgorithm RSA_PSS_PSS_SHA_384 = new TlsV13Signature(0x080a);
        public static final TlsSignatureAlgorithm RSA_PSS_PSS_SHA_512 = new TlsV13Signature(0x080b);
        public static final TlsSignatureAlgorithm RSA_PKCS_1_SHA_256 = new TlsV13Signature(0x0401);
        public static final TlsSignatureAlgorithm RSA_PKCS_1_SHA_384 = new TlsV13Signature(0x0501);
        public static final TlsSignatureAlgorithm RSA_PKCS_1_SHA_512 = new TlsV13Signature(0x0601);
        public static final TlsSignatureAlgorithm RSA_PKCS_1_SHA_224 = new TlsV13Signature(0x0301);
        public static final TlsSignatureAlgorithm RSA_PKCS_1_SHA_1 = new TlsV13Signature(0x0201);
        public static final TlsSignatureAlgorithm DSA_SHA_256 = new TlsV13Signature(0x0402);
        public static final TlsSignatureAlgorithm DSA_SHA_384 = new TlsV13Signature(0x0502);
        public static final TlsSignatureAlgorithm DSA_SHA_512 = new TlsV13Signature(0x0602);
        public static final TlsSignatureAlgorithm DSA_SHA_224 = new TlsV13Signature(0x0302);
        public static final TlsSignatureAlgorithm DSA_SHA_1 = new TlsV13Signature(0x0202);
        public static final TlsSignatureAlgorithm GOSTR_34102012_256Intrinsic = new TlsV13Signature(0x0840);
        public static final TlsSignatureAlgorithm GOSTR_34102012_512Intrinsic = new TlsV13Signature(0x0841);
        public static final TlsSignatureAlgorithm GOSTR_34102012_256_GOSTR_34112012_256 = new TlsV13Signature(0xeeee);
        public static final TlsSignatureAlgorithm GOSTR_34102012_512_GOSTR_34112012_512 = new TlsV13Signature(0xefef);
        public static final TlsSignatureAlgorithm GOSTR_34102001_GOSTR_3411 = new TlsV13Signature(0xeded);

        private final int id;
        public TlsV13Signature(int id) {
            this.id = id;
        }

        @Override
        public int id() {
            return id;
        }

        @Override
        public boolean equals(Object obj) {
            return obj == this
                    || obj instanceof TlsV13Signature that && this.id() == that.id();
        }

        @Override
        public int hashCode() {
            return Objects.hashCode(id);
        }
    }
}
