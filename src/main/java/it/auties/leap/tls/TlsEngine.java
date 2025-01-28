package it.auties.leap.tls;

import it.auties.leap.tls.certificate.TlsCertificatesHandler;
import it.auties.leap.tls.certificate.TlsCertificatesProvider;
import it.auties.leap.tls.certificate.TlsClientCertificateType;
import it.auties.leap.tls.cipher.TlsCipher;
import it.auties.leap.tls.cipher.mode.TlsCipherMode;
import it.auties.leap.tls.compression.TlsCompression;
import it.auties.leap.tls.exception.TlsException;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.hash.TlsExchangeAuthenticator;
import it.auties.leap.tls.hash.TlsHandshakeHash;
import it.auties.leap.tls.hash.TlsHmac;
import it.auties.leap.tls.key.*;
import it.auties.leap.tls.message.TlsMessage;
import it.auties.leap.tls.message.implementation.*;
import it.auties.leap.tls.signature.TlsSignature;
import it.auties.leap.tls.signature.TlsSignatureAlgorithm;
import it.auties.leap.tls.version.TlsVersion;

import java.io.ByteArrayOutputStream;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.stream.Collectors;

public class TlsEngine {
    private final Config localConfig;
    private final TlsRandomData localRandomData;
    private final TlsSharedSecret localSessionId;

    private final ByteArrayOutputStream messageDigestBuffer;
    private final CopyOnWriteArrayList<TlsMessage.Type> processedMessageTypes;

    private volatile Mode mode;

    private final InetSocketAddress remoteAddress;
    private volatile TlsRandomData remoteRandomData;
    private volatile TlsSharedSecret remoteSessionId;

    private volatile TlsCipher negotiatedCipher;
    private volatile TlsHandshakeHash handshakeHash;
    private volatile TlsCompression negotiatedCompression;

    private volatile TlsCipherMode localCipher;
    private volatile TlsCipherMode remoteCipher;

    private volatile TlsExchangeAuthenticator localAuthenticator;
    private volatile TlsExchangeAuthenticator remoteAuthenticator;

    private volatile List<TlsClientCertificateType> remoteCertificateTypes;
    private volatile List<TlsSignature> remoteCertificateAlgorithms;
    private volatile List<String> remoteCertificateAuthorities;

    private volatile ByteBuffer remoteKeyParameters;
    private volatile TlsSignatureAlgorithm remoteKeySignatureAlgorithm;
    private volatile byte[] remoteKeySignature;

    private volatile KeyPair localKeyPair;

    private volatile TlsCookie dtlsCookie;

    private volatile List<TlsSupportedGroup> supportedGroups;
    private volatile boolean extendedMasterSecret;

    private volatile TlsSessionKeys sessionKeys;
    private final Queue<ByteBuffer> bufferedMessages;

    private volatile Map<Integer, TlsCipher> availableCiphers;
    private volatile Map<Byte, TlsCompression> availableCompressions;
    private List<TlsExtension.Concrete> localProcessedExtensions;

    public TlsEngine(InetSocketAddress address, Config config) {
        this.remoteAddress = address;
        this.localConfig = config;
        this.localRandomData = TlsRandomData.random();
        this.localSessionId = TlsSharedSecret.random();
        this.processedMessageTypes = new CopyOnWriteArrayList<>();
        this.dtlsCookie = switch (config.version().protocol()) {
            case TCP -> null;
            case UDP -> TlsCookie.empty();
        };
        this.supportedGroups = List.of(TlsSupportedGroup.ffdhe2048());
        this.messageDigestBuffer = new ByteArrayOutputStream(); // TODO: Calculate optimal space
        this.bufferedMessages = new LinkedList<>();
    }

    public Config config() {
        return localConfig;
    }

    public Optional<TlsCipher> negotiatedCipher() {
        return Optional.ofNullable(negotiatedCipher);
    }

    public Optional<Mode> selectedMode() {
        return Optional.ofNullable(mode);
    }

    public void handleMessage(TlsMessage message) {
        processedMessageTypes.add(message.type());
        System.out.println("Handling " + message.getClass().getName());
        switch (message) {
            case HelloRequestMessage.Server _ -> {
                // This message will be ignored by the client if the client is currently negotiating a session.
                // TODO: Implement logic
            }

            case HelloMessage.Client clientHelloMessage -> {
                switch (message.source()) {
                    case LOCAL -> {
                        if (!Arrays.equals(clientHelloMessage.randomData().data(), localRandomData.data())) {
                            throw new TlsException("Local random data mismatch");
                        }

                        if (!Arrays.equals(clientHelloMessage.sessionId().data(), localSessionId.data())) {
                            throw new TlsException("Local session id mismatch");
                        }

                        this.mode = Mode.CLIENT;
                        this.availableCiphers = clientHelloMessage.ciphers()
                                .stream()
                                .collect(Collectors.toUnmodifiableMap(TlsCipher::id, Function.identity()));
                        this.availableCompressions = clientHelloMessage.compressions()
                                .stream()
                                .collect(Collectors.toUnmodifiableMap(TlsCompression::id, Function.identity()));
                    }
                    case REMOTE -> {
                        this.remoteRandomData = clientHelloMessage.randomData();
                        this.remoteSessionId = clientHelloMessage.sessionId();
                        // TODO: Validate cipher
                    }
                }
            }

            case HelloMessage.Server serverHelloMessage -> {
                switch (message.source()) {
                    case LOCAL -> {
                        if (!Arrays.equals(serverHelloMessage.randomData().data(), localRandomData.data())) {
                            throw new TlsException("Local random data mismatch");
                        }

                        if (!Arrays.equals(serverHelloMessage.sessionId().data(), localSessionId.data())) {
                            throw new TlsException("Local session id mismatch");
                        }

                        this.mode = Mode.SERVER;
                        this.availableCiphers = TlsCipher.allCiphers()
                                .stream()
                                .collect(Collectors.toUnmodifiableMap(TlsCipher::id, Function.identity()));
                        this.availableCompressions = TlsCompression.allCompressions()
                                .stream()
                                .collect(Collectors.toUnmodifiableMap(TlsCompression::id, Function.identity()));
                    }
                    case REMOTE -> {
                        System.out.println("Selected cipher: " + serverHelloMessage.cipher());
                        this.remoteRandomData = serverHelloMessage.randomData();
                        this.remoteSessionId = serverHelloMessage.sessionId();
                        this.negotiatedCipher = serverHelloMessage.cipherId()
                                .map(availableCiphers::get)
                                .orElseThrow(() -> new TlsException("Unknown cipher"));
                        this.negotiatedCompression = serverHelloMessage.compressionId()
                                .map(availableCompressions::get)
                                .orElseThrow(() -> new TlsException("Unknown compression"));
                        this.handshakeHash = TlsHandshakeHash.of(localConfig.version(), negotiatedCipher.newHash());
                    }
                }
            }

            case CertificateMessage.Server certificateMessage -> {
                var certificates = certificateMessage.certificates();
                localConfig.certificatesHandler()
                        .accept(remoteAddress, certificates, mode == Mode.SERVER ? TlsSource.LOCAL : TlsSource.REMOTE);
            }

            case CertificateRequestMessage.Server certificateRequestMessage -> {

                this.remoteCertificateAuthorities = certificateRequestMessage.authorities();
            }

            case KeyExchangeMessage.Server serverKeyExchangeMessage -> {
                this.remoteKeyParameters = serverKeyExchangeMessage.remoteParameters()
                        .orElse(null);
                this.remoteKeySignature = serverKeyExchangeMessage.signature();
            }

            case FinishedMessage.Server serverFinishedMessage -> {
                if(mode == Mode.CLIENT) {
                    // TODO: Validate
                }
            }

            case KeyExchangeMessage.Client client -> {
                var preMasterSecret = client.localParameters()
                        .orElseThrow()
                        .generatePreMasterSecret(localKeyPair.getPrivate(), remoteKeyParameters);
                var masterSecret = TlsMasterSecretKey.of(
                        mode,
                        localConfig.version(),
                        negotiatedCipher,
                        preMasterSecret,
                        extendedMasterSecret ? handshakeHash().orElse(null) : null,
                        localRandomData,
                        remoteRandomData
                );
                this.sessionKeys = TlsSessionKeys.of(
                        mode,
                        localConfig.version(),
                        negotiatedCipher,
                        masterSecret,
                        localRandomData,
                        remoteRandomData
                );
                this.localAuthenticator = TlsExchangeAuthenticator.of(
                        localConfig.version(),
                        TlsHmac.of(negotiatedCipher.newHash()),
                        sessionKeys.localMacKey()
                );
                this.remoteAuthenticator = TlsExchangeAuthenticator.of(
                        localConfig.version(),
                        TlsHmac.of(negotiatedCipher.newHash()),
                        sessionKeys.remoteMacKey()
                );
                this.localCipher = negotiatedCipher.newCipher(
                        localConfig.version(),
                        localAuthenticator,
                        true,
                        sessionKeys.localCipherKey(),
                        sessionKeys.localIv()
                );
                this.remoteCipher = negotiatedCipher.newCipher(
                        localConfig.version(),
                        remoteAuthenticator,
                        false,
                        sessionKeys.remoteCipherKey(),
                        sessionKeys.remoteIv()
                );
            }

            case CertificateMessage.Client certificateMessage -> {
                var certificates = certificateMessage.certificates();
                localConfig.certificatesHandler()
                        .accept(remoteAddress, certificates, mode == Mode.CLIENT ? TlsSource.LOCAL : TlsSource.REMOTE);
            }

            case FinishedMessage.Client clientFinishedMessage -> {
                if(mode == Mode.SERVER) {
                    // TODO: Validate
                }
            }

            case ApplicationDataMessage applicationDataMessage -> {
                if(message.source() == TlsSource.REMOTE) {
                    bufferedMessages.add(applicationDataMessage.message());
                }
            }

            case AlertMessage alertMessage -> throw new IllegalArgumentException("Received alert: " + alertMessage);

            default -> {}
        }
    }

    public boolean isHandshakeComplete() {
        return hasProcessedHandshakeMessage(TlsMessage.Type.SERVER_FINISHED);
    }

    public boolean isLocalCipherEnabled() {
        return switch (mode) {
            case CLIENT -> hasProcessedHandshakeMessage(TlsMessage.Type.CLIENT_CHANGE_CIPHER_SPEC) && hasProcessedHandshakeMessage(TlsMessage.Type.CLIENT_FINISHED);
            case SERVER -> hasProcessedHandshakeMessage(TlsMessage.Type.SERVER_CHANGE_CIPHER_SPEC) && hasProcessedHandshakeMessage(TlsMessage.Type.SERVER_HELLO_DONE);
            case null -> false;
        };
    }

    public boolean isRemoteCipherEnabled() {
        return switch (mode) {
            case CLIENT -> hasProcessedHandshakeMessage(TlsMessage.Type.SERVER_CHANGE_CIPHER_SPEC) && hasProcessedHandshakeMessage(TlsMessage.Type.SERVER_HELLO_DONE);
            case SERVER -> hasProcessedHandshakeMessage(TlsMessage.Type.CLIENT_CHANGE_CIPHER_SPEC) && hasProcessedHandshakeMessage(TlsMessage.Type.CLIENT_FINISHED);
            case null -> false;
        };
    }

    public boolean hasReceivedFragments() {
        return hasProcessedHandshakeMessage(TlsMessage.Type.APPLICATION_DATA);
    }

    public boolean hasProcessedHandshakeMessage(TlsMessage.Type type) {
        return processedMessageTypes.contains(type);
    }

    public TlsRandomData localRandomData() {
        return localRandomData;
    }

    public TlsSharedSecret localSessionId() {
        return localSessionId;
    }

    public Optional<InetSocketAddress> remoteAddress() {
        return Optional.ofNullable(remoteAddress);
    }

    public Optional<KeyPair> localKeyPair() {
        return Optional.ofNullable(localKeyPair);
    }

    public Optional<TlsCookie> localCookie() {
        return Optional.ofNullable(dtlsCookie);
    }

    public void setSupportedGroups(List<TlsSupportedGroup> supportedGroups) {
        this.supportedGroups = supportedGroups;
    }

    public Optional<TlsSupportedGroup> negotiatedGroup() {
        return Optional.empty();
    }

    public void enableExtendedMasterSecret() {
        this.extendedMasterSecret = true;
    }

    public Optional<byte[]> handshakeHash() {
        if(handshakeHash == null) {
            return Optional.empty();
        }else {
            return Optional.ofNullable(handshakeHash.digest());
        }
    }

    public Optional<byte[]> handshakeVerificationData(TlsSource source) {
        if(handshakeHash == null) {
            return Optional.empty();
        }else {
            return Optional.ofNullable(handshakeHash.finish(sessionKeys, mode, source));
        }
    }

    public void updateHandshakeHash(ByteBuffer buffer, int offset) {
        var length = buffer.remaining() - offset;
        for(var i = 0; i < length; i++) {
            messageDigestBuffer.write(buffer.get(buffer.position() + offset + i));
        }
    }

    public void digestHandshakeHash() {
        if(handshakeHash != null) {
            handshakeHash.update(messageDigestBuffer.toByteArray());
            messageDigestBuffer.reset();
        }
    }

    public Optional<TlsSessionKeys> sessionKeys() {
        return Optional.ofNullable(sessionKeys);
    }

    public void encrypt(byte contentType, ByteBuffer input, ByteBuffer output) {
        if(localCipher == null) {
            throw new TlsException("Cannot encrypt a message before enabling the local cipher");
        }

        localCipher.update(contentType, input, output, null);
    }

    public void decrypt(byte contentType, ByteBuffer input, ByteBuffer output) {
        if(remoteCipher == null) {
            throw new TlsException("Cannot decrypt a message before enabling the remote cipher");
        }

       remoteCipher.update(contentType, input, output, null);
    }

    public Optional<ByteBuffer> lastBufferedMessage() {
        return bufferedMessages.isEmpty() ? Optional.empty() : Optional.ofNullable(bufferedMessages.peek());
    }

    public void pollBufferedMessage() {
        bufferedMessages.poll();
    }

    public boolean hasExtension(Predicate<Integer> isGrease) {
        return false;
    }

    public List<TlsExtension.Concrete> processedExtensions() {
        if(localProcessedExtensions == null) {
            processExtensions();
        }

        return localProcessedExtensions;
    }

    public int processedExtensionsLength() {
        if(localProcessedExtensions == null) {
            processExtensions();
        }

        return localProcessedExtensions.stream().mapToInt(TlsExtension.Concrete::extensionLength).sum();
    }

    private void processExtensions() {
        var compatibleExtensions = localConfig.extensions()
                .stream()
                .filter(extension -> extension.versions().contains(localConfig.version()))
                .toList();

        // Make sure there are no conflicts
        var dependenciesTree = new HashMap<Class<? extends TlsExtension>, TlsExtension.Configurable.Dependencies>();
        var seen = new HashSet<Class<? extends TlsExtension>>();
        for (var extension : compatibleExtensions) {
            switch (extension) {
                case TlsExtension.Concrete concrete -> {
                    if (!seen.add(concrete.getClass())) {
                        throw new IllegalArgumentException("Extension with type %s conflicts with previously defined extension".formatted(extension.getClass().getName()));
                    }

                    dependenciesTree.put(concrete.getClass(), TlsExtension.Configurable.Dependencies.none());
                }
                case TlsExtension.Configurable configurableExtension -> {
                    if (!seen.add(configurableExtension.getClass())) {
                        throw new IllegalArgumentException("Model with type %s conflicts with previously defined model".formatted(extension.getClass().getName()));
                    }

                    var concreteType = configurableExtension.decoder()
                            .toConcreteType(Mode.CLIENT);
                    if (!seen.add(concreteType)) {
                        throw new IllegalArgumentException("Extension with type %s, produced by a model with type %s, conflicts with previously defined extension".formatted(extension.getClass().getName(), concreteType.getName()));
                    }

                    dependenciesTree.put(configurableExtension.getClass(), configurableExtension.dependencies());
                }
            }
        }

        // Allocate the rounds and fill them
        var rounds = new ArrayList<List<TlsExtension>>();
        rounds.addFirst(new ArrayList<>()); // Allocate the first round
        rounds.addLast(new ArrayList<>()); // Allocate the last round
        for (var extension : compatibleExtensions) {
            switch (extension) {
                case TlsExtension.Concrete concrete -> {
                    // Concrete extensions don't have any dependencies, so we can always process them at the beginning
                    var firstRound = rounds.getFirst();
                    firstRound.add(concrete);
                }
                case TlsExtension.Configurable configurableExtension -> {
                    switch (configurableExtension.dependencies()) {
                        // If no dependencies are needed, we can process this extension at the beginning
                        case TlsExtension.Configurable.Dependencies.None _ -> {
                            var firstRound = rounds.getFirst();
                            firstRound.add(configurableExtension);
                        }

                        // If some dependencies are needed to process this extension, calculate after how many rounds it should be processed
                        case TlsExtension.Configurable.Dependencies.Some some -> {
                            var roundIndex = getRoundIndex(dependenciesTree, rounds.size(), some);
                            var existingRound = rounds.get(roundIndex);
                            if (existingRound != null) {
                                existingRound.add(configurableExtension);
                            } else {
                                var newRound = new ArrayList<TlsExtension>();
                                newRound.add(configurableExtension);
                                rounds.set(roundIndex, newRound);
                            }
                        }

                        // If all dependencies are needed to process this extension, we can this process this extension at the end
                        case TlsExtension.Configurable.Dependencies.All _ -> {
                            var lastRound = rounds.getLast();
                            lastRound.addFirst(configurableExtension);
                        }
                    }
                }
            }
        }

        // Actually process the annotations
        this.localProcessedExtensions = new ArrayList<>();
        for (var round : rounds) {
            for (var extension : round) {
                switch (extension) {
                    case TlsExtension.Concrete concrete -> localProcessedExtensions.add(concrete);
                    case TlsExtension.Configurable configurable -> configurable.newInstance(this)
                            .ifPresent(localProcessedExtensions::add);
                }
            }
        }
    }

    private int getRoundIndex(Map<Class<? extends TlsExtension>, TlsExtension.Configurable.Dependencies> dependenciesTree, int rounds, TlsExtension.Configurable.Dependencies.Some some) {
        var roundIndex = 0;
        for (var dependency : some.includedTypes()) {
            var match = dependenciesTree.get(dependency);
            switch (match) {
                // All dependencies are linked to this match: we must process this extension as last
                case TlsExtension.Configurable.Dependencies.All _ -> {
                    return rounds - 1; // No need to process further, this is already the max value we can find
                }

                // Some dependencies are linked to this match: recursively compute the depth
                case TlsExtension.Configurable.Dependencies.Some innerSome ->
                        roundIndex = Math.max(roundIndex, getRoundIndex(dependenciesTree, rounds, innerSome) + 1);

                // No dependencies are linked to this match: nothing to add to our dependencies processing queue
                case TlsExtension.Configurable.Dependencies.None _ -> {
                }

                // No match exists in our dependency tree
                case null -> {
                }
            }
        }
        return roundIndex;
    }

    public OptionalInt explicitNonceLength() {
        return localCipher != null ? OptionalInt.of(localCipher.ivLength().total()) : OptionalInt.empty();
    }

    public static final class Config {
        private static final Config DEFAULT = Config.builder().build();

        private final TlsVersion version;
        private final List<TlsCipher> ciphers;
        private final List<TlsExtension> extensions;
        private final List<TlsCompression> compressions;
        private final TlsCertificatesProvider certificatesProvider;
        private final TlsCertificatesHandler certificatesHandler;

        public Config(
                TlsVersion version,
                List<TlsCipher> ciphers,
                List<TlsExtension> extensions,
                List<TlsCompression> compressions,
                TlsCertificatesProvider certificatesProvider,
                TlsCertificatesHandler certificatesHandler
        ) {
            this.version = version;
            this.ciphers = ciphers;
            this.extensions = extensions;
            this.compressions = compressions;
            this.certificatesProvider = certificatesProvider;
            this.certificatesHandler = certificatesHandler;
        }

        public TlsVersion version() {
            return version;
        }

        public List<TlsCipher> ciphers() {
            return Collections.unmodifiableList(ciphers);
        }

        public List<TlsExtension> extensions() {
            return Collections.unmodifiableList(extensions);
        }

        public List<TlsCompression> compressions() {
            return Collections.unmodifiableList(compressions);
        }

        public Optional<TlsCertificatesProvider> certificatesProvider() {
            return Optional.ofNullable(certificatesProvider);
        }

        public TlsCertificatesHandler certificatesHandler() {
            return certificatesHandler;
        }

        public static Builder builder() {
            return new Builder();
        }

        public static Config defaults() {
            return DEFAULT;
        }

        public static final class Builder {
            private TlsVersion version;
            private List<TlsCipher> ciphers;
            private List<TlsExtension> extensions;
            private List<TlsCompression> compressions;
            private TlsCertificatesProvider certificatesProvider;
            private TlsCertificatesHandler certificatesHandler;
            private Builder() {

            }

            public Builder version(TlsVersion version) {
                this.version = version;
                return this;
            }

            public Builder ciphers(List<TlsCipher> ciphers) {
                this.ciphers = ciphers;
                return this;
            }

            public Builder extensions(List<TlsExtension> extensions) {
                this.extensions = extensions;
                return this;
            }

            public Builder compressions(List<TlsCompression> compressions) {
                this.compressions = compressions;
                return this;
            }

            public Builder certificatesProvider(TlsCertificatesProvider certificatesProvider) {
                this.certificatesProvider = certificatesProvider;
                return this;
            }

            public Builder certificatesHandler(TlsCertificatesHandler certificatesHandler) {
                this.certificatesHandler = certificatesHandler;
                return this;
            }

            public Config build() {
                return new Config(
                        Objects.requireNonNull(this.version, "Missing tls version"),
                        Objects.requireNonNullElseGet(ciphers, TlsCipher::secureCiphers),
                        Objects.requireNonNull(extensions, "Missing tls extensions"),
                        Objects.requireNonNullElseGet(compressions, () -> List.of(TlsCompression.none())),
                        certificatesProvider,
                        Objects.requireNonNullElseGet(certificatesHandler, TlsCertificatesHandler::validate)
                );
            }
        }
    }

    public enum Mode {
        CLIENT,
        SERVER
    }
}
