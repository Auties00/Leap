package it.auties.leap.tls.connection;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.hash.TlsHash;
import it.auties.leap.tls.hash.TlsHashFactory;
import it.auties.leap.tls.hash.TlsHmac;
import it.auties.leap.tls.hash.TlsPrf;
import it.auties.leap.tls.property.TlsProperty;
import it.auties.leap.tls.version.TlsVersion;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.util.Arrays;

public final class TlsConnectionHandshakeHash extends ByteArrayOutputStream {
    private Delegate delegate;

    public TlsConnectionHandshakeHash() {

    }

    public void init(TlsVersion version, TlsHashFactory factory) {
        if(delegate != null) {
            throw new TlsAlert("Already initialized", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
        }

        this.delegate = Delegate.of(version, factory);
        var buffered = this.toByteArray();
        this.reset();
        delegate.update(buffered, 0, buffered.length);
    }

    public void update(ByteBuffer input) {
        if(delegate != null) {
            delegate.update(input);
        }else {
            while (input.hasRemaining()) {
                this.write(input.get());
            }
        }
    }

    public byte[] digest() {
        if(delegate == null) {
            throw new TlsAlert("Not initialized", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
        }

        return delegate.digest();
    }

    public byte[] finish(TlsContext context, TlsSource source) {
        if(delegate == null) {
            throw new TlsAlert("Not initialized", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
        }

        return delegate.finish(context, source);
    }

    private sealed interface Delegate {
        static Delegate of(TlsVersion version, TlsHashFactory hash) {
            return switch (version) {
                case TLS13, DTLS13 -> new TLS13(hash.newHash());
                case TLS12, DTLS12 -> new TLS12(hash.newHash());
                case TLS10, TLS11, DTLS10 -> new TLS10();
            };
        }

        void update(byte[] input, int offset, int length);

        void update(ByteBuffer buffer);

        byte[] digest();

        byte[] finish(TlsContext context, TlsSource source);

        default boolean useClientLabel(TlsSource source, TlsConnectionType mode) {
            return (mode == TlsConnectionType.CLIENT && source == TlsSource.LOCAL)
                    || (mode == TlsConnectionType.SERVER && source == TlsSource.REMOTE);
        }

        final class TLS10 implements Delegate {
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
                var mode = context.localConnectionState().type();
                var masterSecret = context.masterSecretKey()
                        .orElseThrow(() -> new TlsAlert("Master secret key is not available yet", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR));
                var useClientLabel = useClientLabel(source, mode);
                var tlsLabel = useClientLabel ? "client finished" : "server finished";
                var digest = new byte[36];
                var offset = md5.digest(digest, 0, md5.length(), false);
                sha1.digest(digest, offset, sha1.length(), false);
                var result = TlsPrf.tls10Prf(
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

        final class TLS12 implements Delegate {
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
                var masterSecret = context.masterSecretKey()
                        .orElseThrow(() -> new TlsAlert("Master secret key is not available yet", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR));
                var useClientLabel = useClientLabel(source, context.localConnectionState().type());
                var tlsLabel = useClientLabel ? "client finished" : "server finished";
                var result = TlsPrf.tls12Prf(
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

        final class TLS13 implements Delegate {
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
                var cipher = context.getNegotiatedValue(TlsProperty.cipher())
                        .orElseThrow(() -> new TlsAlert("Missing negotiated property: cipher", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR));
                var hashFactory = cipher.hashFactory();
                var connection = switch (source) {
                    case LOCAL -> context.localConnectionState();
                    case REMOTE -> context.remoteConnectionState()
                            .orElseThrow(() -> new TlsAlert("No remote connection state was created", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR));
                };
                var secret = connection.handshakeSecret()
                        .orElseThrow(() -> new TlsAlert("No connection handshake secret was set", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR));
                System.out.println("Finished secret key: " + Arrays.toString(secret.data()));
                var finishedSecret = TlsConnectionSecret.of(hashFactory, "tls13 finished", new byte[0], secret.data(), hashFactory.length());
                secret.destroy();
                var hmac = TlsHmac.of(hashFactory);
                System.out.println("Finished secret: " + Arrays.toString(finishedSecret.data()));
                hmac.init(finishedSecret.data());
                System.out.println("Data: " + Arrays.toString(hash.digest(false)));
                hmac.update(hash.digest(false));
                var result = hmac.doFinal();
                finishedSecret.destroy();
                System.out.println("Finished: " + Arrays.toString(result));
                return result;
            }
        }
    }
}
