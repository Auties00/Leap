package it.auties.leap.tls.signature;

import it.auties.leap.tls.exception.TlsException;

import java.net.URI;
import java.util.Objects;

public final class TlsSignatureAlgorithm implements TlsSignature {
    public static TlsSignature of(TlsSignatureAlgorithm.Signature signature, TlsSignatureAlgorithm.Hash hash) {
        return new TlsSignatureAlgorithm(signature, hash);
    }

    private final Signature signature;
    private final Hash hash;
    private TlsSignatureAlgorithm(Signature signature, Hash hash) {
        this.hash = hash;
        this.signature = signature;
    }

    @Override
    public int id() {
        return (hash.id() << 8) | signature.id();
    }

    @Override
    public boolean equals(Object other) {
        return this == other || other instanceof TlsSignatureAlgorithm that
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

        public static Signature gostr34102012_256() {
            return GOSTR34102012_256;
        }

        public static Signature gostr34102012_512() {
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
