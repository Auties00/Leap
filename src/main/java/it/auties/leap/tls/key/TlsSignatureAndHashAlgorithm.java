package it.auties.leap.tls.key;

import it.auties.leap.tls.config.TlsIdentifiable;
import it.auties.leap.tls.exception.TlsException;

import java.net.URI;
import java.util.Objects;

// https://www.iana.org/assignments/tls-parameters/tls-signaturescheme.csv
public sealed interface TlsSignatureAndHashAlgorithm extends TlsIdentifiable.Int32<TlsSignatureAndHashAlgorithm> {
    static TlsSignatureAndHashAlgorithm signatureAndHash(SignatureAndHash.Signature signature, SignatureAndHash.Hash hash) {
        return new SignatureAndHash(signature, hash);
    }

    static TlsSignatureAndHashAlgorithm ecdsaSecp256r1Sha256() {
        return V13.ECDSA_SECP_256_R1_SHA256;
    }

    static TlsSignatureAndHashAlgorithm ecdsaSecp384r1Sha384() {
        return V13.ECDSA_SECP_384_R1_SHA384;
    }

    static TlsSignatureAndHashAlgorithm ecdsaSecp521r1Sha512() {
        return V13.ECDSA_SECP_521_R1_SHA512;
    }

    static TlsSignatureAndHashAlgorithm ecdsaSha224() {
        return V13.ECDSA_SHA224;
    }

    static TlsSignatureAndHashAlgorithm ecdsaSha1() {
        return V13.ECDSA_SHA1;
    }

    static TlsSignatureAndHashAlgorithm rsaPssRsaeSha256() {
        return V13.RSA_PSS_RSAE_SHA256;
    }

    static TlsSignatureAndHashAlgorithm rsaPssRsaeSha384() {
        return V13.RSA_PSS_RSAE_SHA384;
    }

    static TlsSignatureAndHashAlgorithm rsaPssRsaeSha512() {
        return V13.RSA_PSS_RSAE_SHA512;
    }

    static TlsSignatureAndHashAlgorithm ed25519() {
        return V13.ED25519;
    }

    static TlsSignatureAndHashAlgorithm ed448() {
        return V13.ED448;
    }

    static TlsSignatureAndHashAlgorithm rsaPssPssSha256() {
        return V13.RSA_PSS_PSS_SHA256;
    }

    static TlsSignatureAndHashAlgorithm rsaPssPssSha384() {
        return V13.RSA_PSS_PSS_SHA384;
    }

    static TlsSignatureAndHashAlgorithm rsaPssPssSha512() {
        return V13.RSA_PSS_PSS_SHA512;
    }

    static TlsSignatureAndHashAlgorithm rsaPkcs1Sha256() {
        return V13.RSA_PKCS_1_SHA256;
    }

    static TlsSignatureAndHashAlgorithm rsaPkcs1Sha384() {
        return V13.RSA_PKCS_1_SHA384;
    }

    static TlsSignatureAndHashAlgorithm rsaPkcs1Sha512() {
        return V13.RSA_PKCS_1_SHA512;
    }

    static TlsSignatureAndHashAlgorithm rsaPkcs1Sha224() {
        return V13.RSA_PKCS_1_SHA224;
    }

    static TlsSignatureAndHashAlgorithm rsaPkcs1Sha1() {
        return V13.RSA_PKCS_1_SHA1;
    }

    static TlsSignatureAndHashAlgorithm dsaSha256() {
        return V13.DSA_SHA256;
    }

    static TlsSignatureAndHashAlgorithm dsaSha384() {
        return V13.DSA_SHA384;
    }

    static TlsSignatureAndHashAlgorithm dsaSha512() {
        return V13.DSA_SHA512;
    }

    static TlsSignatureAndHashAlgorithm dsaSha224() {
        return V13.DSA_SHA224;
    }

    static TlsSignatureAndHashAlgorithm dsaSha1() {
        return V13.DSA_SHA1;
    }

    static TlsSignatureAndHashAlgorithm gostr34102012256Intrinsic() {
        return V13.GOSTR_34102012_256Intrinsic;
    }

    static TlsSignatureAndHashAlgorithm gostr34102012512Intrinsic() {
        return V13.GOSTR_34102012_512Intrinsic;
    }

    static TlsSignatureAndHashAlgorithm gostr34102012256Gostr34112012_256() {
        return V13.GOSTR_34102012_256_GOSTR_34112012_256;
    }

    static TlsSignatureAndHashAlgorithm gostr34102012512Gostr34112012512() {
        return V13.GOSTR_34102012_512_GOSTR_34112012_512;
    }

    static TlsSignatureAndHashAlgorithm gostr34102001Gostr3411() {
        return V13.GOSTR_34102001_GOSTR_3411;
    }

    static TlsSignatureAndHashAlgorithm reservedForPrivateUse(int id) {
        return new V13(id);
    }

    Integer id();

    final class SignatureAndHash implements TlsSignatureAndHashAlgorithm {
        private final Signature signature;
        private final Hash hash;
        private SignatureAndHash(Signature signature, Hash hash) {
            this.hash = hash;
            this.signature = signature;
        }

        @Override
        public Integer id() {
            return (hash.id() << 8) | signature.id();
        }

        @Override
        public boolean equals(Object other) {
            return this == other || other instanceof SignatureAndHash that
                    && Objects.equals(signature, that.signature)
                    && Objects.equals(hash, that.hash);
        }

        @Override
        public int hashCode() {
            return Objects.hash(signature, hash);
        }

        public static final class Signature {
            private static final Signature ANONYMOUS = new Signature((byte) 0, false);
            private static final Signature RSA = new Signature((byte) 1, false);
            private static final Signature DSA = new Signature((byte) 2, false);
            private static final Signature ECDSA = new Signature((byte) 3, false);
            private static final Signature RSA_PSS_RSAE_SHA256 = new Signature((byte) 4, true);
            private static final Signature RSA_PSS_RSAE_SHA384 = new Signature((byte) 5, true);
            private static final Signature RSA_PSS_RSAE_SHA512 = new Signature((byte) 6, true);
            private static final Signature ED25519 = new Signature((byte) 7, true);
            private static final Signature ED448 = new Signature((byte) 8, true);
            private static final Signature RSA_PSS_PSS_SHA256 = new Signature((byte) 9, true);
            private static final Signature RSA_PSS_PSS_SHA384 = new Signature((byte) 10, true);
            private static final Signature RSA_PSS_PSS_SHA512 = new Signature((byte) 11, true);
            private static final Signature GOSTR34102012_256 = new Signature((byte) 64, false);
            private static final Signature GOSTR34102012_512 = new Signature((byte) 65, false);


            public static Signature anonymous() {
                return ANONYMOUS;
            }

            public static Signature rsa() {
                return RSA;
            }

            public static Signature dsa() {
                return DSA;
            }

            public static Signature ecdsa() {
                return ECDSA;
            }

            public static Signature rsaPssRsaeSha256() {
                return RSA_PSS_RSAE_SHA256;
            }

            public static Signature rsaPssRsaeSha384() {
                return RSA_PSS_RSAE_SHA384;
            }

            public static Signature rsaPssRsaeSha512() {
                return RSA_PSS_RSAE_SHA512;
            }

            public static Signature ed25519() {
                return ED25519;
            }

            public static Signature ed448() {
                return ED448;
            }

            public static Signature rsaPssPssSha256() {
                return RSA_PSS_PSS_SHA256;
            }

            public static Signature rsaPssPssSha384() {
                return RSA_PSS_PSS_SHA384;
            }

            public static Signature rsaPssPssSha512() {
                return RSA_PSS_PSS_SHA512;
            }

            public static Signature gostr34102012256() {
                return GOSTR34102012_256;
            }

            public static Signature gostr34102012512() {
                return GOSTR34102012_512;
            }

            public static Hash reservedForPrivateUse(byte id) {
                if (id != -32 && id != -31) {
                    throw new TlsException(
                            "Only values from 224-255 (decimal) inclusive are reserved for Private Use",
                            URI.create("https://www.rfc-editor.org/rfc/rfc5246.html"),
                            "12"
                    );
                }

                return new Hash(id);
            }

            private final byte id;
            private final boolean intrinsicHash;

            private Signature(byte id, boolean intrinsicHash) {
                this.id = id;
                this.intrinsicHash = intrinsicHash;
            }

            public byte id() {
                return id;
            }

            public boolean intrinsicHash() {
                return intrinsicHash;
            }
        }

        public static final class Hash {
            private static final Hash NONE = new Hash((byte) 0);
            private static final Hash MD5 = new Hash((byte) 1);
            private static final Hash SHA1 = new Hash((byte) 2);
            private static final Hash SHA224 = new Hash((byte) 3);
            private static final Hash SHA256 = new Hash((byte) 4);
            private static final Hash SHA384 = new Hash((byte) 5);
            private static final Hash SHA512 = new Hash((byte) 6);
            private static final Hash INTRINSIC = new Hash((byte) 8);

            public static Hash none() {
                return NONE;
            }

            public static Hash md5() {
                return MD5;
            }

            public static Hash sha1() {
                return SHA1;
            }

            public static Hash sha224() {
                return SHA224;
            }

            public static Hash sha256() {
                return SHA256;
            }

            public static Hash sha384() {
                return SHA384;
            }

            public static Hash sha512() {
                return SHA512;
            }

            public static Hash intrinsic() {
                return INTRINSIC;
            }

            public static Hash reservedForPrivateUse(byte id) {
                if (id != -32 && id != -31) {
                    throw new TlsException(
                            "Only values from 224-255 (decimal) inclusive are reserved for Private Use",
                            URI.create("https://www.rfc-editor.org/rfc/rfc5246.html"),
                            "12"
                    );
                }

                return new Hash(id);
            }

            private final byte id;

            private Hash(byte id) {
                this.id = id;
            }

            public byte id() {
                return id;
            }
        }
    }

    final class V13 implements TlsSignatureAndHashAlgorithm {
        private static final TlsSignatureAndHashAlgorithm ECDSA_SECP_256_R1_SHA256 = new V13(0x0403);
        private static final TlsSignatureAndHashAlgorithm ECDSA_SECP_384_R1_SHA384 = new V13(0x0503);
        private static final TlsSignatureAndHashAlgorithm ECDSA_SECP_521_R1_SHA512 = new V13(0x0603);
        private static final TlsSignatureAndHashAlgorithm ECDSA_SHA224 = new V13(0x0303);
        private static final TlsSignatureAndHashAlgorithm ECDSA_SHA1 = new V13(0x0203);
        private static final TlsSignatureAndHashAlgorithm RSA_PSS_RSAE_SHA256 = new V13(0x0408);
        private static final TlsSignatureAndHashAlgorithm RSA_PSS_RSAE_SHA384 = new V13(0x0805);
        private static final TlsSignatureAndHashAlgorithm RSA_PSS_RSAE_SHA512 = new V13(0x0806);
        private static final TlsSignatureAndHashAlgorithm ED25519 = new V13(0x0807);
        private static final TlsSignatureAndHashAlgorithm ED448 = new V13(0x0808);
        private static final TlsSignatureAndHashAlgorithm RSA_PSS_PSS_SHA256 = new V13(0x0809);
        private static final TlsSignatureAndHashAlgorithm RSA_PSS_PSS_SHA384 = new V13(0x080a);
        private static final TlsSignatureAndHashAlgorithm RSA_PSS_PSS_SHA512 = new V13(0x080b);
        private static final TlsSignatureAndHashAlgorithm RSA_PKCS_1_SHA256 = new V13(0x0401);
        private static final TlsSignatureAndHashAlgorithm RSA_PKCS_1_SHA384 = new V13(0x0501);
        private static final TlsSignatureAndHashAlgorithm RSA_PKCS_1_SHA512 = new V13(0x0601);
        private static final TlsSignatureAndHashAlgorithm RSA_PKCS_1_SHA224 = new V13(0x0301);
        private static final TlsSignatureAndHashAlgorithm RSA_PKCS_1_SHA1 = new V13(0x0201);
        private static final TlsSignatureAndHashAlgorithm DSA_SHA256 = new V13(0x0402);
        private static final TlsSignatureAndHashAlgorithm DSA_SHA384 = new V13(0x0502);
        private static final TlsSignatureAndHashAlgorithm DSA_SHA512 = new V13(0x0602);
        private static final TlsSignatureAndHashAlgorithm DSA_SHA224 = new V13(0x0302);
        private static final TlsSignatureAndHashAlgorithm DSA_SHA1 = new V13(0x0202);
        private static final TlsSignatureAndHashAlgorithm GOSTR_34102012_256Intrinsic = new V13(0x0840);
        private static final TlsSignatureAndHashAlgorithm GOSTR_34102012_512Intrinsic = new V13(0x0841);
        private static final TlsSignatureAndHashAlgorithm GOSTR_34102012_256_GOSTR_34112012_256 = new V13(0xeeee);
        private static final TlsSignatureAndHashAlgorithm GOSTR_34102012_512_GOSTR_34112012_512 = new V13(0xefef);
        private static final TlsSignatureAndHashAlgorithm GOSTR_34102001_GOSTR_3411 = new V13(0xeded);

        private final int id;
        private V13(int id) {
            this.id = id;
        }

        @Override
        public Integer id() {
            return id;
        }

        @Override
        public boolean equals(Object other) {
            return other == this || other instanceof V13 that
                    && Objects.equals(this.id(), that.id());
        }

        @Override
        public int hashCode() {
            return Objects.hash(id);
        }
    }
}
