package it.auties.leap.tls.hash;

import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsMode;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.exception.TlsException;
import it.auties.leap.tls.version.TlsVersion;

import java.util.Arrays;

public abstract sealed class TlsHandshakeHash {
    public static TlsHandshakeHash of(TlsVersion version, TlsHashFactory hash) {
        return switch (version) {
            case TLS13, DTLS13 -> new T13VerifyDataGenerator(hash.newHash());
            case TLS12, DTLS12 -> new T12VerifyDataGenerator(hash.newHash());
            case TLS10, TLS11, DTLS10 -> new T10VerifyDataGenerator();
            case SSL30 -> new S30VerifyDataGenerator();
        };
    }

    public abstract void update(byte[] input);
    public abstract byte[] digest();
    public abstract byte[] finish(TlsContext context, TlsSource source);

    private static final class S30VerifyDataGenerator extends TlsHandshakeHash {
        private static final byte[] MD5_PAD1 = genPad(0x36, 48);
        private static final byte[] MD5_PAD2 = genPad(0x5c, 48);
        private static final byte[] SHA_PAD1 = genPad(0x36, 40);
        private static final byte[] SHA_PAD2 = genPad(0x5c, 40);
        private static final byte[] SSL_CLIENT = { 0x43, 0x4C, 0x4E, 0x54 };
        private static final byte[] SSL_SERVER = { 0x53, 0x52, 0x56, 0x52 };

        private static byte[] genPad(int b, int count) {
            byte[] padding = new byte[count];
            Arrays.fill(padding, (byte)b);
            return padding;
        }

        private final TlsHash md5;
        private final TlsHash sha1;

        private S30VerifyDataGenerator() {
            this.md5 = TlsHash.md5();
            this.sha1 = TlsHash.sha1();
        }

        @Override
        public void update(byte[] input) {
            md5.update(input);
            sha1.update(input);
        }

        @Override
        public byte[] digest() {
            var digest = new byte[36];
            var md5Length = md5.digest(digest, false);
            sha1.digest(digest, md5Length, false);
            return digest;
        }

        @Override
        public byte[] finish(TlsContext context, TlsSource source) {
            var mode = context.selectedMode()
                    .orElseThrow(() -> new TlsException("No mode was selected yet"));
            var masterSecret = context.masterSecretKey()
                    .orElseThrow(() -> new TlsException("Master secret key is not available yet"))
                    .data();
            var useClientLabel = (mode == TlsMode.CLIENT && source == TlsSource.LOCAL) || (mode == TlsMode.SERVER && source == TlsSource.REMOTE);
            if (useClientLabel) {
                md5.update(SSL_CLIENT);
                sha1.update(SSL_CLIENT);
            } else {
                md5.update(SSL_SERVER);
                sha1.update(SSL_SERVER);
            }

            md5.update(masterSecret);
            md5.update(MD5_PAD1);
            var md5Temp = md5.digest(false);
            md5.update(masterSecret);
            md5.update(MD5_PAD2);
            md5.update(md5Temp);

            sha1.update(masterSecret);
            sha1.update(SHA_PAD1);
            var sha1Temp = sha1.digest(false);
            sha1.update(masterSecret);
            sha1.update(SHA_PAD2);
            sha1.update(sha1Temp);

            var digest = new byte[36];
            System.arraycopy(md5.digest(false), 0, digest, 0, 16);
            System.arraycopy(sha1.digest(false), 0, digest, 16, 20);

            return digest;
        }
    }

    private static final class T10VerifyDataGenerator extends TlsHandshakeHash {
        private final TlsHash md5;
        private final TlsHash sha1;

        private T10VerifyDataGenerator() {
            this.md5 = TlsHash.md5();
            this.sha1 = TlsHash.sha1();
        }

        @Override
        public void update(byte[] input) {
            md5.update(input);
            sha1.update(input);
        }

        @Override
        public byte[] digest() {
            var digest = new byte[36];
            var md5Length = md5.digest(digest, 0, 16, false);
            sha1.digest(digest, md5Length, 20, false);
            return digest;
        }

        @Override
        public byte[] finish(TlsContext context, TlsSource source) {
            var mode = context.selectedMode()
                    .orElseThrow(() -> new TlsException("No mode was selected yet"));
            var masterSecret = context.masterSecretKey()
                    .orElseThrow(() -> new TlsException("Master secret key is not available yet"))
                    .data();
            var useClientLabel = (mode == TlsMode.CLIENT && source == TlsSource.LOCAL) || (mode == TlsMode.SERVER && source == TlsSource.REMOTE);
            var tlsLabel = useClientLabel ? "client finished" : "server finished";
            return TlsPRF.tls10Prf(
                    masterSecret,
                    tlsLabel.getBytes(),
                    digest(),
                    12,
                    TlsHash.none(),
                    TlsHash.none()
            );
        }
    }

    private static final class T12VerifyDataGenerator extends TlsHandshakeHash {
        private final TlsHash hash;
        private T12VerifyDataGenerator(TlsHash hash) {
            this.hash = hash;
        }

        @Override
        public void update(byte[] input) {
            hash.update(input);
        }

        @Override
        public byte[] digest() {
            return hash.digest(false);
        }

        @Override
        public byte[] finish(TlsContext context, TlsSource source) {
            var mode = context.selectedMode()
                    .orElseThrow(() -> new TlsException("No mode was selected yet"));
            var masterSecret = context.masterSecretKey()
                    .orElseThrow(() -> new TlsException("Master secret key is not available yet"))
                    .data();
            var useClientLabel = (mode == TlsMode.CLIENT && source == TlsSource.LOCAL) || (mode == TlsMode.SERVER && source == TlsSource.REMOTE);
            var tlsLabel = useClientLabel ? "client finished" : "server finished";
            return TlsPRF.tls12Prf(
                    masterSecret,
                    tlsLabel.getBytes(),
                    digest(),
                    12,
                    hash.duplicate()
            );
        }
    }

    private static final class T13VerifyDataGenerator extends TlsHandshakeHash {
        private static final byte[] HKDF_LABEL = "tls13 finished".getBytes();
        private static final byte[] HKDF_CONTEXT = new byte[0];

        private final TlsHash hash;
        private T13VerifyDataGenerator(TlsHash hash) {
            this.hash = hash;
        }

        @Override
        public void update(byte[] input) {
            hash.update(input);
        }

        @Override
        public byte[] digest() {
            return hash.digest(false);
        }

        @Override
        public byte[] finish(TlsContext context, TlsSource source) {
              /*
            TODO
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
