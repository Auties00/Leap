package it.auties.leap.tls.key;

import java.security.KeyPair;
import java.security.PublicKey;

public sealed interface TlsKeyPair {
    static TlsKeyPair of(byte[] publicKey, KeyPair jceKeyPair) {
        return new Local(publicKey, jceKeyPair);
    }

    static TlsKeyPair of(PublicKey jcePublicKey) {
        return new Remote(jcePublicKey);
    }

    PublicKey jcaPublicKey();

    final class Local implements TlsKeyPair {
        private final byte[] publicKey;
        private final KeyPair jcaPublicKey;
        private Local(byte[] publicKey, KeyPair jcaPublicKey) {
            this.publicKey = publicKey;
            this.jcaPublicKey = jcaPublicKey;
        }

        public byte[] publicKey() {
            return publicKey;
        }

        public KeyPair jceKeyPair() {
            return jcaPublicKey;
        }

        @Override
        public PublicKey jcaPublicKey() {
            return jcaPublicKey.getPublic();
        }
    }

    final class Remote implements TlsKeyPair {
        private final PublicKey jcePublicKey;
        private Remote(PublicKey jcePublicKey) {
            this.jcePublicKey = jcePublicKey;
        }

        public PublicKey jcaPublicKey() {
            return jcePublicKey;
        }
    }
}
