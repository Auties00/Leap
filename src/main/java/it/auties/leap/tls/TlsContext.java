package it.auties.leap.tls;

import it.auties.leap.tls.certificate.TlsClientCertificateType;
import it.auties.leap.tls.cipher.TlsCipher;
import it.auties.leap.tls.cipher.TlsCipherMode;
import it.auties.leap.tls.cipher.TlsExchangeAuthenticator;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchange;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchangeType;
import it.auties.leap.tls.compression.TlsCompression;
import it.auties.leap.tls.exception.TlsException;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.hash.TlsHandshakeHash;
import it.auties.leap.tls.hash.TlsHash;
import it.auties.leap.tls.hash.TlsHashFactory;
import it.auties.leap.tls.hash.TlsPRF;
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
import java.security.PublicKey;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import static it.auties.leap.tls.util.BufferUtils.readBytes;
import static it.auties.leap.tls.util.TlsKeyConstants.*;

public class TlsContext {
    private final TlsConfig localConfig;
    private final TlsRandomData localRandomData;
    private final TlsSharedSecret localSessionId;

    private final ByteArrayOutputStream messageDigestBuffer;
    private final CopyOnWriteArrayList<TlsMessage.Type> processedMessageTypes;

    private volatile TlsMode mode;

    private final InetSocketAddress remoteAddress;
    private volatile TlsRandomData remoteRandomData;
    private volatile TlsSharedSecret remoteSessionId;

    private volatile TlsCipher negotiatedCipher;
    private volatile TlsHandshakeHash handshakeHash;
    private volatile TlsCompression negotiatedCompression;

    private volatile TlsCipherMode localCipher;
    private volatile TlsCipherMode remoteCipher;
    private volatile TlsMasterSecretKey localMasterSecretKey;

    private volatile TlsExchangeAuthenticator localAuthenticator;
    private volatile TlsExchangeAuthenticator remoteAuthenticator;

    private volatile List<TlsClientCertificateType> remoteCertificateTypes;
    private volatile List<TlsSignature> remoteCertificateAlgorithms;
    private volatile List<String> remoteCertificateAuthorities;

    private volatile TlsKeyExchange localKeyExchange;
    private volatile TlsKeyExchange remoteKeyExchange;
    private volatile TlsSignatureAlgorithm remoteKeySignatureAlgorithm;
    private volatile byte[] remoteKeySignature;

    private volatile KeyPair localKeyPair;

    private volatile TlsCookie dtlsCookie;

    private volatile List<TlsSupportedGroup> supportedGroups;
    private volatile boolean extendedMasterSecret;
    
    private final Queue<ByteBuffer> bufferedMessages;

    private volatile Map<Integer, TlsCipher> availableCiphers;
    private volatile Map<Byte, TlsCompression> availableCompressions;
    private List<TlsExtension.Concrete> localProcessedExtensions;
    private int localProcessedExtensionsLength;
    private PublicKey remotePublicKey;

    public TlsContext(InetSocketAddress address, TlsConfig config) {
        this.remoteAddress = address;
        this.localConfig = config;
        this.localRandomData = TlsRandomData.random();
        this.localSessionId = TlsSharedSecret.random();
        this.processedMessageTypes = new CopyOnWriteArrayList<>();
        this.dtlsCookie = switch (config.version().protocol()) {
            case TCP -> null;
            case UDP -> TlsCookie.empty();
        };
        this.supportedGroups = List.of();
        this.messageDigestBuffer = new ByteArrayOutputStream(); // TODO: Calculate optimal space
        this.bufferedMessages = new LinkedList<>();
    }

    public TlsConfig config() {
        return localConfig;
    }

    public Optional<TlsCipher> negotiatedCipher() {
        return Optional.ofNullable(negotiatedCipher);
    }

    public Optional<TlsMode> selectedMode() {
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

                        this.mode = TlsMode.CLIENT;
                        this.availableCiphers = clientHelloMessage.ciphers()
                                .stream()
                                .collect(Collectors.toUnmodifiableMap(TlsCipher::id, Function.identity(), (element, _) -> element));
                        this.availableCompressions = clientHelloMessage.compressions()
                                .stream()
                                .collect(Collectors.toUnmodifiableMap(TlsCompression::id, Function.identity(), (element, _) -> element));
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

                        this.mode = TlsMode.SERVER;
                        this.availableCiphers = TlsCipher.allCiphers()
                                .stream()
                                .collect(Collectors.toUnmodifiableMap(TlsCipher::id, Function.identity(), (element, _) -> element));
                        this.availableCompressions = TlsCompression.allCompressions()
                                .stream()
                                .collect(Collectors.toUnmodifiableMap(TlsCompression::id, Function.identity(), (element, _) -> element));
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
                        this.handshakeHash = TlsHandshakeHash.of(localConfig.version(), negotiatedCipher.hashFactory());
                    }
                }
            }

            case CertificateMessage.Server certificateMessage -> {
                var certificates = certificateMessage.certificates();
                this.remotePublicKey = localConfig.certificatesHandler()
                        .accept(remoteAddress, certificates, switch (mode) {
                            case CLIENT -> TlsSource.REMOTE;
                            case SERVER -> TlsSource.LOCAL;
                        })
                        .getPublicKey();
                if(negotiatedCipher.keyExchangeFactory().type() == TlsKeyExchangeType.STATIC) {
                    this.localKeyExchange = negotiatedCipher.keyExchangeFactory()
                            .newLocalKeyExchange(this);
                }
            }

            case CertificateRequestMessage.Server certificateRequestMessage -> {

                this.remoteCertificateAuthorities = certificateRequestMessage.authorities();
            }

            case KeyExchangeMessage.Server serverKeyExchangeMessage -> {
                this.remoteKeyExchange = serverKeyExchangeMessage.parameters();
                if(negotiatedCipher.keyExchangeFactory().type() != TlsKeyExchangeType.EPHEMERAL) {
                    throw new TlsException("Unexpected server key exchange message for static key exchange");
                }

                this.localKeyExchange = negotiatedCipher.keyExchangeFactory()
                        .newLocalKeyExchange(this);
            }

            case FinishedMessage.Server serverFinishedMessage -> {
                if(mode == TlsMode.CLIENT) {
                    // TODO: Validate
                }
            }

            case KeyExchangeMessage.Client client -> {
                var preMasterSecret = client.localParameters()
                        .orElseThrow()
                        .preMasterSecretGenerator()
                        .generatePreMasterSecret(this);
                initKeys(preMasterSecret);
            }

            case CertificateMessage.Client certificateMessage -> {
                var certificates = certificateMessage.certificates();
                localConfig.certificatesHandler()
                        .accept(remoteAddress, certificates, mode == TlsMode.CLIENT ? TlsSource.LOCAL : TlsSource.REMOTE);
            }

            case FinishedMessage.Client clientFinishedMessage -> {
                if(mode == TlsMode.SERVER) {
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

    public Optional<byte[]> getHandshakeVerificationData(TlsSource source) {
        if(handshakeHash == null) {
            return Optional.empty();
        }else {
            return Optional.ofNullable(handshakeHash.finish(this, source));
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

        return localProcessedExtensionsLength;
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
                            .toConcreteType(TlsMode.CLIENT);
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
                    case TlsExtension.Concrete concrete -> {
                        localProcessedExtensions.add(concrete);
                        localProcessedExtensionsLength += concrete.extensionLength();
                    }
                    case TlsExtension.Configurable configurable -> configurable.newInstance(this).ifPresent(concrete -> {
                        localProcessedExtensions.add(concrete);
                        localProcessedExtensionsLength += concrete.extensionLength();
                    });
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

    public Optional<TlsKeyExchange> localKeyExchange() {
        return Optional.ofNullable(localKeyExchange);
    }


    public Optional<TlsKeyExchange> remoteKeyExchange() {
        return Optional.ofNullable(remoteKeyExchange);
    }

    private void initKeys(byte[] preMasterSecret) {
        System.out.println("Pre master secret: " + Arrays.toString(preMasterSecret));
        this.localMasterSecretKey = TlsMasterSecretKey.of(
                mode,
                localConfig.version(),
                negotiatedCipher,
                preMasterSecret,
                extendedMasterSecret ? handshakeHash().orElse(null) : null,
                localRandomData,
                remoteRandomData
        );
        var clientRandom = switch (mode) {
            case CLIENT -> localRandomData.data();
            case SERVER -> remoteRandomData.data();
        };
        var serverRandom = switch (mode) {
            case SERVER -> localRandomData.data();
            case CLIENT -> remoteRandomData.data();
        };

        var localCipherEngine = negotiatedCipher.engineFactory()
                .newCipherEngine();
        var localCipherMode = negotiatedCipher.modeFactory()
                .newCipherMode(localCipherEngine);

        var remoteCipherEngine = negotiatedCipher.engineFactory()
                .newCipherEngine();
        var remoteCipherMode = negotiatedCipher.modeFactory()
                .newCipherMode(remoteCipherEngine);

        this.localCipher = localCipherMode;
        this.remoteCipher = remoteCipherMode;
        
        var macLength = negotiatedCipher.hashFactory()
                .length();
        var expandedKeyLength = localCipherEngine.exportedKeyLength();
        var keyLength = localCipherEngine.keyLength();

        var ivLength = switch (localCipher) {
            case TlsCipherMode.Block block -> {
                if (block.isAEAD()) {
                    yield localCipher.ivLength().fixed();
                }

                if(localConfig.version().id().value() >= TlsVersion.TLS11.id().value()) {
                    yield 0;
                }

                yield localCipher.ivLength().total();
            }
            case TlsCipherMode.Stream _ -> localCipher.ivLength().total();
        };

        var keyBlockLen = (macLength + keyLength + (expandedKeyLength.isPresent() ? 0 : ivLength)) * 2;
        var keyBlock = generateBlock(localConfig.version(), negotiatedCipher.hashFactory(), localMasterSecretKey.data(), clientRandom, serverRandom, keyBlockLen);

        var clientMacKey = macLength != 0 ? readBytes(keyBlock, macLength) : null;
        var serverMacKey = macLength != 0 ? readBytes(keyBlock, macLength) : null;

        var localMacKey = switch (mode) {
            case CLIENT -> clientMacKey;
            case SERVER -> serverMacKey;
        };
        var remoteMacKey = switch (mode) {
            case CLIENT -> serverMacKey;
            case SERVER -> clientMacKey;
        };

        var localAuthenticator = TlsExchangeAuthenticator.of(
                localConfig.version(),
                negotiatedCipher.hashFactory(),
                localMacKey
        );
        var remoteAuthenticator = TlsExchangeAuthenticator.of(
                localConfig.version(),
                negotiatedCipher.hashFactory(),
                remoteMacKey
        );

        if (keyLength == 0) {
            localCipherEngine.init(true, null);
            remoteCipherEngine.init(false, null);
            localCipherMode.init(null, null);
            remoteCipherMode.init(null, null);
            return;
        }

        var clientKey = readBytes(keyBlock, keyLength);
        var serverKey = readBytes(keyBlock, keyLength);
        if (expandedKeyLength.isEmpty()) {
            var localKey = switch (mode) {
                case CLIENT -> clientKey;
                case SERVER -> serverKey;
            };
            var remoteKey = switch (mode) {
                case CLIENT -> serverKey;
                case SERVER -> clientKey;
            };

            var clientIv = ivLength == 0 ? null : readBytes(keyBlock, ivLength);
            var serverIv = ivLength == 0 ? null : readBytes(keyBlock, ivLength);
            var localIv = switch (mode) {
                case CLIENT -> clientIv;
                case SERVER -> serverIv;
            };
            var remoteIv = switch (mode) {
                case CLIENT -> serverIv;
                case SERVER -> clientIv;
            };

            localCipherEngine.init(true, localKey);
            remoteCipherEngine.init(false, remoteKey);
            localCipherMode.init(localAuthenticator, localIv);
            remoteCipherMode.init(remoteAuthenticator, remoteIv);
            return;
        }

        switch (localConfig.version()) {
            case SSL30 -> {
                var md5 = TlsHash.md5();
                md5.update(clientKey);
                md5.update(clientRandom);
                md5.update(serverRandom);
                var expandedClientKey = md5.digest(true, 0, expandedKeyLength.getAsInt());

                md5.update(serverKey);
                md5.update(serverRandom);
                md5.update(clientRandom);
                var expandedServerKey = md5.digest(true, 0, expandedKeyLength.getAsInt());

                var localKey = switch (mode) {
                    case CLIENT -> expandedClientKey;
                    case SERVER -> expandedServerKey;
                };
                var remoteKey = switch (mode) {
                    case CLIENT -> expandedServerKey;
                    case SERVER -> expandedClientKey;
                };

                localCipherEngine.init(true, localKey);
                remoteCipherEngine.init(false, remoteKey);

                if (ivLength == 0) {
                    localCipherMode.init(localAuthenticator, new byte[0]);
                    remoteCipherMode.init(remoteAuthenticator, new byte[0]);
                }else {
                    md5.update(clientRandom);
                    md5.update(serverRandom);
                    var clientIv = md5.digest(true, 0, ivLength);

                    md5.update(serverRandom);
                    md5.update(clientRandom);
                    var serverIv = md5.digest(true, 0, ivLength);

                    var localIv = switch (mode) {
                        case CLIENT -> clientIv;
                        case SERVER -> serverIv;
                    };
                    var remoteIv = switch (mode) {
                        case CLIENT -> serverIv;
                        case SERVER -> clientIv;
                    };
                    localCipherMode.init(localAuthenticator, localIv);
                    remoteCipherMode.init(remoteAuthenticator, remoteIv);
                }
            }

            case TLS10 -> {
                var seed = TlsPRF.seed(clientRandom, serverRandom);
                var expandedClientKey = TlsPRF.tls10Prf(clientKey, LABEL_CLIENT_WRITE_KEY, seed, expandedKeyLength.getAsInt());
                var expandedServerKey = TlsPRF.tls10Prf(serverKey, LABEL_SERVER_WRITE_KEY, seed, expandedKeyLength.getAsInt());

                var localKey = switch (mode) {
                    case CLIENT -> expandedClientKey;
                    case SERVER -> expandedServerKey;
                };
                var remoteKey = switch (mode) {
                    case CLIENT -> expandedServerKey;
                    case SERVER -> expandedClientKey;
                };

                localCipherEngine.init(true, localKey);
                remoteCipherEngine.init(false, remoteKey);
                
                if (ivLength == 0) {
                    localCipherMode.init(localAuthenticator, new byte[0]);
                    remoteCipherMode.init(remoteAuthenticator, new byte[0]);
                }else {
                    var block = TlsPRF.tls10Prf(null, LABEL_IV_BLOCK, seed, ivLength << 1);
                    var clientIv = Arrays.copyOf(block, ivLength);
                    var serverIv = Arrays.copyOfRange(block, ivLength, ivLength << 2);

                    var localIv = switch (mode) {
                        case CLIENT -> clientIv;
                        case SERVER -> serverIv;
                    };
                    var remoteIv = switch (mode) {
                        case CLIENT -> serverIv;
                        case SERVER -> clientIv;
                    };
                    
                    localCipherMode.init(localAuthenticator, localIv);
                    remoteCipherMode.init(remoteAuthenticator, remoteIv);
                }
            }

            default -> throw new TlsException("TLS 1.1+ should not be negotiating exportable ciphersuites");
        }
    }

    private static ByteBuffer generateBlock(TlsVersion version, TlsHashFactory hashFactory, byte[] masterSecret, byte[] clientRandom, byte[] serverRandom, int keyBlockLen) {
        return switch (version) {
            case SSL30 -> generateBlockSSL30(masterSecret, clientRandom, serverRandom, keyBlockLen);
            case TLS10, TLS11 -> generateBlockTls11(masterSecret, clientRandom, serverRandom, keyBlockLen);
            default -> generateBlock(hashFactory, masterSecret, clientRandom, serverRandom, keyBlockLen);
        };
    }

    private static ByteBuffer generateBlockSSL30(byte[] masterSecret, byte[] clientRandom, byte[] serverRandom, int keyBlockLen) {
        var md5 = TlsHash.md5();
        var sha = TlsHash.sha1();
        var keyBlock = new byte[keyBlockLen];
        var tmp = new byte[20];
        for (int i = 0, remaining = keyBlockLen; remaining > 0; i++, remaining -= 16) {
            sha.update(SSL3_CONSTANT[i]);
            sha.update(masterSecret);
            sha.update(serverRandom);
            sha.update(clientRandom);
            sha.digest(tmp, 0, 20, true);

            md5.update(masterSecret);
            md5.update(tmp);

            if (remaining >= 16) {
                md5.digest(keyBlock, i << 4, 16, true);
            } else {
                md5.digest(tmp, 0, 16, true);
                System.arraycopy(tmp, 0, keyBlock, i << 4, remaining);
            }
        }
        return ByteBuffer.wrap(keyBlock);
    }

    private static ByteBuffer generateBlockTls11(byte[] masterSecret, byte[] clientRandom, byte[] serverRandom, int keyBlockLen) {
        var seed = TlsPRF.seed(serverRandom, clientRandom);
        var result = TlsPRF.tls10Prf(
                masterSecret,
                LABEL_KEY_EXPANSION,
                seed,
                keyBlockLen
        );
        return ByteBuffer.wrap(result);
    }

    private static ByteBuffer generateBlock(TlsHashFactory factory, byte[] masterSecret, byte[] clientRandom, byte[] serverRandom, int keyBlockLen) {
        var seed = TlsPRF.seed(serverRandom, clientRandom);
        var result = TlsPRF.tls12Prf(
                masterSecret,
                LABEL_KEY_EXPANSION,
                seed,
                keyBlockLen,
                factory.newHash()
        );
        return ByteBuffer.wrap(result);
    }

    public Optional<TlsCipherMode> localCipher() {
        return Optional.ofNullable(localCipher);
    }

    public Optional<TlsCipherMode> remoteCipher() {
        return Optional.ofNullable(remoteCipher);
    }

    public Optional<TlsMasterSecretKey> masterSecretKey() {
        return Optional.ofNullable(localMasterSecretKey);
    }

    public Optional<PublicKey> remotePublicKey() {
        return Optional.ofNullable(remotePublicKey);
    }

    public void setLocalKeyPair(KeyPair keyPair) {
        this.localKeyPair = keyPair;
    }

    public List<TlsSupportedGroup> supportedGroups() {
        return supportedGroups;
    }
}
