package it.auties.leap.tls.connection.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsContextMode;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.hash.TlsHash;
import it.auties.leap.tls.hash.TlsHashFactory;
import it.auties.leap.tls.hash.TlsPRF;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;

public sealed abstract class ConnectionIntegrityDelegate {
    public static ConnectionIntegrityDelegate of(TlsVersion version, TlsHashFactory hash) {
        return switch (version) {
            case TLS13, DTLS13 -> new ConnectionIntegrityDelegate.TLS13(hash.newHash());
            case TLS12, DTLS12 -> new ConnectionIntegrityDelegate.TLS12(hash.newHash());
            case TLS10, TLS11, DTLS10 -> new ConnectionIntegrityDelegate.TLS10();
        };
    }

    public abstract void update(byte[] input, int offset, int length);

    public abstract void update(ByteBuffer buffer);

    public abstract byte[] digest();

    public abstract byte[] finish(TlsContext context, TlsSource source);

    boolean useClientLabel(TlsSource source, TlsContextMode mode) {
        return (mode == TlsContextMode.CLIENT && source == TlsSource.LOCAL)
                || (mode == TlsContextMode.SERVER && source == TlsSource.REMOTE);
    }

    private static final class TLS10 extends ConnectionIntegrityDelegate {
        private final TlsHash md5;
        private final TlsHash sha1;

        public TLS10() {
            this.md5 = TlsHash.md5();
            this.sha1 = TlsHash.sha1();
        }

        @Override
        public void update(byte[] input, int offset, int length) {
            md5.update(input, offset, length);
            sha1.update(input, offset, length);
        }

        @Override
        public void update(ByteBuffer input) {
            var position = input.position();
            md5.update(input);
            input.position(position);
            sha1.update(input);
        }

        @Override
        public byte[] digest() {
            var digest = new byte[36];
            var offset = md5.digest(digest, 0, md5.length(), false);
            sha1.digest(digest, offset, sha1.length(), false);
            return digest;
        }

        @Override
        public byte[] finish(TlsContext context, TlsSource source) {
            var mode = context.mode()
                    ;
            var masterSecret = context.masterSecretKey()
                    .orElseThrow(() -> new TlsAlert("Master secret key is not available yet"));
            var useClientLabel = useClientLabel(source, mode);
            var tlsLabel = useClientLabel ? "client finished" : "server finished";
            var digest = new byte[36];
            var offset = md5.digest(digest, 0, md5.length(), false);
            sha1.digest(digest, offset, sha1.length(), false);
            var result = TlsPRF.tls10Prf(
                    masterSecret.data(),
                    tlsLabel.getBytes(),
                    digest,
                    12,
                    TlsHash.none(),
                    TlsHash.none()
            );
            if(useClientLabel) {
                masterSecret.destroy();
            }
            return result;
        }
    }

    private static final class TLS12 extends ConnectionIntegrityDelegate {
        private final TlsHash hash;

        public TLS12(TlsHash hash) {
            this.hash = hash;
        }

        @Override
        public void update(byte[] input, int offset, int length) {
            hash.update(input, offset, length);
        }

        @Override
        public void update(ByteBuffer input) {
            hash.update(input);
        }

        @Override
        public byte[] digest() {
            return hash.digest(false);
        }

        @Override
        public byte[] finish(TlsContext context, TlsSource source) {
            var mode = context.mode();
            var masterSecret = context.masterSecretKey()
                    .orElseThrow(() -> new TlsAlert("Master secret key is not available yet"));
            var useClientLabel = useClientLabel(source, mode);
            var tlsLabel = useClientLabel ? "client finished" : "server finished";
            var result = TlsPRF.tls12Prf(
                    masterSecret.data(),
                    tlsLabel.getBytes(),
                    hash.digest(false),
                    12,
                    hash.duplicate()
            );
            if(useClientLabel) {
                masterSecret.destroy();
            }
            return result;
        }
    }

    private static final class TLS13 extends ConnectionIntegrityDelegate {
        private static final byte[] HKDF_LABEL = "tls13 finished".getBytes();
        private static final byte[] HKDF_CONTEXT = new byte[0];

        private final TlsHash hash;

        public TLS13(TlsHash hash) {
            this.hash = hash;
        }

        @Override
        public void update(byte[] input, int offset, int length) {
            hash.update(input, offset, length);
        }

        @Override
        public void update(ByteBuffer input) {
            hash.update(input);
        }

        @Override
        public byte[] digest() {
            return hash.digest(false);
        }

        @Override
        public byte[] finish(TlsContext context, TlsSource source) {
            /*
            sun.security.ssl.Finished
                 var hash = context.getNegotiatedValue(TlsProperty.ciphers())
                    .orElseThrow(() -> TlsException.noNegotiatedProperty(TlsProperty.ciphers()))
                    .hashFactory()
                    .newHash();

            var hkdf = TlsHkdf.of(TlsHmac.of(hash));
            hkdf.expand()

            var hmac = TlsHmac.of(hash);
            hmac.init(finishedSecret);
            hmac.update(handshakeHash);
            return hmac.doFinal();

            CipherSuite.HashAlg hashAlg = context.negotiatedCipherSuite.hashAlg;
            SecretKey secret = isValidation ? context.baseReadSecret : context.baseWriteSecret;
            SSLBasicKeyDerivation kdf = new SSLBasicKeyDerivation(secret, hashAlg.name, hkdfLabel, hkdfContext, hashAlg.hashLength);
            AlgorithmParameterSpec keySpec = new SSLBasicKeyDerivation.SecretSizeSpec(hashAlg.hashLength);
            SecretKey finishedSecret = kdf.deriveKey("TlsFinishedSecret", keySpec);

            String hmacAlg = "Hmac" + hashAlg.name.replace("-", "");
            Mac hmac = Mac.getInstance(hmacAlg);
            hmac.init(finishedSecret);
            return hmac.doFinal(context.handshakeHash.digest());
             */
            throw new UnsupportedOperationException();
        }
    }
}
