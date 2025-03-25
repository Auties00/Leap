package it.auties.leap.tls;

import it.auties.leap.socket.SocketProtocol;
import it.auties.leap.tls.certificate.TlsCertificatesHandler;
import it.auties.leap.tls.certificate.TlsCertificatesProvider;
import it.auties.leap.tls.cipher.TlsCipher;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchange;
import it.auties.leap.tls.compression.TlsCompression;
import it.auties.leap.tls.connection.TlsConnection;
import it.auties.leap.tls.connection.TlsConnectionInitializer;
import it.auties.leap.tls.connection.masterSecret.TlsMasterSecretGenerator;
import it.auties.leap.tls.connection.preMasterSecret.TlsPreMasterSecretGenerator;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.hash.TlsHash;
import it.auties.leap.tls.hash.TlsHashFactory;
import it.auties.leap.tls.hash.TlsPRF;
import it.auties.leap.tls.message.TlsMessageDeserializer;
import it.auties.leap.tls.property.TlsProperty;
import it.auties.leap.tls.util.TlsExtensionsUtils;
import it.auties.leap.tls.version.TlsVersion;

import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.security.KeyStore;
import java.util.*;
import java.util.function.Supplier;

@SuppressWarnings({"UnusedReturnValue", "unchecked"})
public class TlsContext {
    private final TlsCertificatesProvider certificatesProvider;
    private final TlsCertificatesHandler certificatesHandler;
    private final KeyStore trustedKeyStore;
    private final TlsMessageDeserializer messageDeserializer;
    private final TlsMasterSecretGenerator masterSecretGenerator;
    private final TlsConnectionInitializer connectionInitializer;
    private final TlsConnection localConnectionState;
    private final Map<TlsProperty<?, ?>, PropertyValue<?, ?>> properties;
    private final Queue<ByteBuffer> bufferedMessages;
    private volatile InetSocketAddress remoteAddress;
    private volatile TlsMode mode;
    private volatile TlsConnection remoteConnectionState;
    private volatile TlsKeyExchange localKeyExchange;
    private volatile TlsKeyExchange remoteKeyExchange;

    TlsContext(
            List<TlsVersion> versions,
            List<TlsExtension> extensions,
            List<TlsCipher> ciphers,
            List<TlsCompression> compressions,
            TlsConnection localConnectionState,
            TlsCertificatesProvider certificatesProvider,
            TlsCertificatesHandler certificatesHandler,
            KeyStore trustedKeyStore,
            TlsMessageDeserializer messageDeserializer,
            TlsMasterSecretGenerator masterSecretGenerator,
            TlsConnectionInitializer connectionInitializer
    ) {
        this.localConnectionState = localConnectionState;
        this.certificatesProvider = certificatesProvider;
        this.certificatesHandler = certificatesHandler;
        this.trustedKeyStore = trustedKeyStore;
        this.messageDeserializer = messageDeserializer;
        this.masterSecretGenerator = masterSecretGenerator;
        this.connectionInitializer = connectionInitializer;
        this.properties = new HashMap<>();
        this.bufferedMessages = new LinkedList<>();
        addNegotiableProperty(TlsProperty.version(), versions);
        addNegotiableProperty(TlsProperty.extensions(), extensions, () -> TlsExtensionsUtils.process(this));
        addNegotiableProperty(TlsProperty.cipher(), ciphers);
        addNegotiableProperty(TlsProperty.compression(), compressions);
    }

    public static TlsContextBuilder newBuilder(SocketProtocol protocol) {
        return new TlsContextBuilder(protocol);
    }

    public KeyStore trustedKeyStore() {
        return trustedKeyStore;
    }

    public Optional<TlsMode> selectedMode() {
        return Optional.ofNullable(mode);
    }

    public TlsCertificatesHandler certificatesHandler() {
        return certificatesHandler;
    }

    public TlsCertificatesProvider certificatesProvider() {
        return certificatesProvider;
    }

    public TlsConnection localConnectionState() {
        return localConnectionState;
    }

    public Optional<TlsConnection> remoteConnectionState() {
        return Optional.ofNullable(remoteConnectionState);
    }

    public TlsMessageDeserializer messageDeserializer() {
        return messageDeserializer;
    }

    public Optional<InetSocketAddress> remoteAddress() {
        return Optional.ofNullable(remoteAddress);
    }

    public TlsContext setRemoteConnectionState(TlsConnection remoteConnectionState) {
        this.remoteConnectionState = remoteConnectionState;
        return this;
    }

    public TlsContext setSelectedMode(TlsMode mode) {
        this.mode = mode;
        return this;
    }

    public TlsContext setRemoteAddress(InetSocketAddress remoteAddress) {
        this.remoteAddress = remoteAddress;
        return this;
    }

    public <I, O> TlsContext addNegotiableProperty(TlsProperty<I, O> property, I propertyValue) {
        var value = PropertyValue.of(propertyValue);
        properties.put(property, value);
        return this;
    }

    public <I, O> TlsContext addNegotiableProperty(TlsProperty<I, O> property, I propertyValue, Supplier<O> negotiatedValue) {
        var value = PropertyValue.ofLazy(propertyValue, negotiatedValue);
        properties.put(property, value);
        return this;
    }

    public <I, O> TlsContext addNegotiatedProperty(TlsProperty<I, O> property, O propertyValue) {
        var value = (PropertyValue<I, O>) properties.get(property);
        if(value == null) {
            throw new TlsException("Missing property: " + property.id());
        }

        value.setNegotiated(propertyValue);
        return this;
    }

    public boolean removeProperty(TlsProperty<?, ?> property) {
        return properties.remove(property) != null;
    }

    public <I, O> Optional<I> getNegotiableValue(TlsProperty<I, O> property) {
        var value = (PropertyValue<I, O>) properties.get(property);
        if(value == null) {
            return Optional.empty();
        }

        return Optional.ofNullable(value.negotiable());
    }

    public <I, O> Optional<O> getNegotiatedValue(TlsProperty<I, O> property) {
        var value = (PropertyValue<I, O>) properties.get(property);
        if (value == null) {
            return Optional.empty();
        }

        return value.negotiated();
    }

    public TlsContext addBufferedMessage(ByteBuffer buffer) {
        bufferedMessages.add(buffer);
        return this;
    }

    public Optional<ByteBuffer> lastBufferedMessage() {
        return bufferedMessages.isEmpty() ? Optional.empty() : Optional.ofNullable(bufferedMessages.peek());
    }

    public void pollBufferedMessage() {
        bufferedMessages.poll();
    }

    public TlsMasterSecretGenerator masterSecretGenerator() {
        return masterSecretGenerator;
    }

    public TlsConnectionInitializer connectionInitializer() {
        return connectionInitializer;
    }

    private sealed abstract static class PropertyValue<I, O> {
        public static <I, O> PropertyValue<I, O> of(I negotiable) {
            return new Static<>(negotiable);
        }

        public static <I, O> PropertyValue<I, O> ofLazy(I negotiable, Supplier<O> supplier) {
            return new Lazy<>(negotiable, supplier);
        }

        private final I negotiable;
        private PropertyValue(I negotiable) {
            this.negotiable = negotiable;
        }

        public I negotiable() {
            return negotiable;
        }

        public abstract Optional<O> negotiated();

        public abstract void setNegotiated(O negotiated);

        private static final class Static<I, O> extends PropertyValue<I, O> {
            private O value;
            private Static(I negotiable) {
                super(negotiable);
            }

            @Override
            public Optional<O> negotiated() {
                return Optional.ofNullable(value);
            }

            @Override
            public void setNegotiated(O negotiated) {
                this.value = negotiated;
            }
        }

        private static final class Lazy<I, O> extends PropertyValue<I, O> {
            private Supplier<O> supplier;
            private O value;
            private Lazy(I negotiable, Supplier<O> supplier) {
                super(negotiable);
                this.supplier = supplier;
            }

            @Override
            public Optional<O> negotiated() {
                if(supplier != null) {
                    this.value = supplier.get();
                    this.supplier = null;
                }

                return Optional.ofNullable(value);
            }

            @Override
            public void setNegotiated(O negotiated) {
                this.supplier = null;
                this.value = negotiated;
            }
        }
    }

    private sealed interface TlsHandshakeHash {
        static TlsHandshakeHash of(TlsVersion version, TlsHashFactory hash) {
            return switch (version) {
                case TLS13, DTLS13 -> new T13VerifyDataGenerator(hash.newHash());
                case TLS12, DTLS12 -> new T12VerifyDataGenerator(hash.newHash());
                case TLS10, TLS11, DTLS10 -> new T10VerifyDataGenerator();
                case SSL30 -> new S30VerifyDataGenerator();
            };
        }

        void update(byte[] input);
        byte[] digest(TlsMode mode, TlsSource source);
        default boolean useClientLabel(TlsSource source, TlsMode mode) {
            return (mode == TlsMode.CLIENT && source == TlsSource.LOCAL)
                    || (mode == TlsMode.SERVER && source == TlsSource.REMOTE);
        }

        final class S30VerifyDataGenerator implements TlsHandshakeHash {
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
            public byte[] digest(TlsMode mode, TlsSource source) {
                var masterSecret = context.masterSecretKey()
                        .orElseThrow(() -> new TlsException("Master secret key is not available yet"))
                        .data();
                var useClientLabel = useClientLabel(source, mode);
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
                var offset = md5.digest(digest, 0, md5.length(), false);
                sha1.digest(digest, offset, sha1.length(), false);

                return digest;
            }
        }

        final class T10VerifyDataGenerator implements TlsHandshakeHash {
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
            public byte[] digest(TlsMode mode, TlsSource source) {
                var masterSecret = context.masterSecretKey()
                        .orElseThrow(() -> new TlsException("Master secret key is not available yet"))
                        .data();
                var useClientLabel = useClientLabel(source, mode);
                var tlsLabel = useClientLabel ? "client finished" : "server finished";
                var digest = new byte[36];
                var offset = md5.digest(digest, 0, md5.length(), false);
                sha1.digest(digest, offset, sha1.length(), false);
                return TlsPRF.tls10Prf(
                        masterSecret,
                        tlsLabel.getBytes(),
                        digest,
                        12,
                        TlsHash.none(),
                        TlsHash.none()
                );
            }
        }

        final class T12VerifyDataGenerator implements TlsHandshakeHash {
            private final TlsHash hash;
            private T12VerifyDataGenerator(TlsHash hash) {
                this.hash = hash;
            }

            @Override
            public void update(byte[] input) {
                hash.update(input);
            }

            @Override
            public byte[] digest(TlsMode mode, TlsSource source) {
                var masterSecret = context.masterSecretKey()
                        .orElseThrow(() -> new TlsException("Master secret key is not available yet"))
                        .data();
                var useClientLabel = useClientLabel(source, mode);
                var tlsLabel = useClientLabel ? "client finished" : "server finished";
                return TlsPRF.tls12Prf(
                        masterSecret,
                        tlsLabel.getBytes(),
                        hash.digest(false),
                        12,
                        hash.duplicate()
                );
            }
        }

        final class T13VerifyDataGenerator implements TlsHandshakeHash {
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
            public byte[] digest(TlsMode mode, TlsSource source) {
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
}
