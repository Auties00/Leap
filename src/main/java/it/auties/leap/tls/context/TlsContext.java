package it.auties.leap.tls.context;

import it.auties.leap.tls.certificate.TlsClientCertificateType;
import it.auties.leap.tls.cipher.TlsCipher;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchange;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchangeType;
import it.auties.leap.tls.cipher.mode.TlsCipherMode;
import it.auties.leap.tls.compression.TlsCompression;
import it.auties.leap.tls.exception.TlsException;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.extension.implementation.SupportedGroupsExtension;
import it.auties.leap.tls.group.TlsSupportedCurve;
import it.auties.leap.tls.group.TlsSupportedFiniteField;
import it.auties.leap.tls.group.TlsSupportedGroup;
import it.auties.leap.tls.hash.TlsHandshakeHash;
import it.auties.leap.tls.hash.TlsHash;
import it.auties.leap.tls.hash.TlsHashFactory;
import it.auties.leap.tls.hash.TlsPRF;
import it.auties.leap.tls.mac.TlsExchangeMac;
import it.auties.leap.tls.message.TlsMessage;
import it.auties.leap.tls.message.implementation.*;
import it.auties.leap.tls.secret.TlsMasterSecret;
import it.auties.leap.tls.signature.TlsSignature;
import it.auties.leap.tls.signature.TlsSignatureAlgorithm;
import it.auties.leap.tls.util.TlsKeyUtils;
import it.auties.leap.tls.version.TlsVersion;

import java.io.ByteArrayOutputStream;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import static it.auties.leap.tls.util.BufferUtils.readBytes;
import static it.auties.leap.tls.util.TlsKeyUtils.*;

public class TlsContext {
    private final TlsConfig localConfig;
    private final byte[] localRandomData;
    private final byte[] localSessionId;

    private final ByteArrayOutputStream messageDigestBuffer;

    private volatile TlsMode mode;

    private final InetSocketAddress remoteAddress;
    private volatile byte[] remoteRandomData;
    private volatile byte[] remoteSessionId;

    private volatile TlsCipher negotiatedCipher;
    private volatile TlsHandshakeHash handshakeHash;
    private volatile TlsCompression negotiatedCompression;

    private volatile TlsCipherMode localCipher;
    private volatile TlsCipherMode remoteCipher;
    private volatile TlsMasterSecret localMasterSecretKey;

    private volatile TlsExchangeMac localAuthenticator;
    private volatile TlsExchangeMac remoteAuthenticator;

    private volatile List<TlsClientCertificateType> remoteCertificateTypes;
    private volatile List<TlsSignature> remoteCertificateAlgorithms;
    private volatile CertificateRequestMessage.Server certificateRequestMessage;

    private volatile TlsKeyExchange localKeyExchange;
    private volatile TlsKeyExchange remoteKeyExchange;
    private volatile TlsSignatureAlgorithm remoteKeySignatureAlgorithm;
    private volatile byte[] remoteKeySignature;

    private volatile KeyPair localKeyPair;

    private volatile byte[] dtlsCookie;

    private volatile List<TlsSupportedGroup> localSupportedGroups;
    private volatile TlsSupportedCurve localPreferredEllipticCurve;
    private volatile TlsSupportedFiniteField localPreferredFiniteField;
    private volatile boolean extendedMasterSecret;
    
    private final Queue<ByteBuffer> bufferedMessages;

    private volatile Map<Integer, TlsCipher> availableCiphers;
    private volatile Map<Byte, TlsCompression> availableCompressions;
    private List<TlsExtension.Concrete> localProcessedExtensions;
    private int localProcessedExtensionsLength;
    private PublicKey remotePublicKey;
    private byte[] preMasterSecret;
    private List<X509Certificate> remoteCertificates;
    private List<X509Certificate> localCertificates;

    private volatile boolean localHelloDone;
    private volatile boolean remoteHelloDone;
    private volatile boolean localCipherEnabled;
    private volatile boolean remoteCipherEnabled;
    private volatile boolean localHandshakeComplete;
    private volatile boolean remoteHandshakeComplete;

    public TlsContext(InetSocketAddress address, TlsConfig config) {
        this.remoteAddress = address;
        this.localConfig = config;
        this.localRandomData = TlsKeyUtils.randomData();
        this.localSessionId = TlsKeyUtils.randomData();
        this.dtlsCookie = switch (config.version().protocol()) {
            case TCP -> null;
            case UDP -> TlsKeyUtils.randomData();
        };
        this.messageDigestBuffer = new ByteArrayOutputStream(); // TODO: Calculate optimal space
        this.bufferedMessages = new LinkedList<>();
        setLocalSupportedGroups(SupportedGroupsExtension.Configurable.recommendedGroups());
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

    public boolean update(TlsMessage message) {
        System.out.println("Processing " + message.getClass().getName());
        switch (message) {
            case HelloRequestMessage.Server _ -> {
                // This message will be ignored by the client if the client is currently negotiating a session.
                // TODO: Implement logic
            }

            case HelloMessage.Client clientHelloMessage -> {
                switch (message.source()) {
                    case LOCAL -> {
                        if (!Arrays.equals(clientHelloMessage.randomData(), localRandomData)) {
                            throw new TlsException("Local random data mismatch");
                        }

                        if (!Arrays.equals(clientHelloMessage.sessionId(), localSessionId)) {
                            throw new TlsException("Local session id mismatch");
                        }

                        this.mode = TlsMode.CLIENT;
                        var ciphers = new HashSet<>(clientHelloMessage.ciphers());
                        this.availableCiphers = localConfig.ciphers()
                                .stream()
                                .filter(cipher -> ciphers.contains(cipher.id()) && cipher.versions().contains(localConfig.version()))
                                .collect(Collectors.toUnmodifiableMap(TlsCipher::id, Function.identity(), (element, _) -> element));
                        var compressions = new HashSet<>(clientHelloMessage.compressions());
                        this.availableCompressions = localConfig.compressions()
                                .stream()
                                .filter(compression -> compressions.contains(compression.id()))
                                .collect(Collectors.toUnmodifiableMap(TlsCompression::id, Function.identity(), (element, _) -> element));
                        this.localHelloDone = true;
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
                        if (!Arrays.equals(serverHelloMessage.randomData(), localRandomData)) {
                            throw new TlsException("Local random data mismatch");
                        }

                        if (!Arrays.equals(serverHelloMessage.sessionId(), localSessionId)) {
                            throw new TlsException("Local session id mismatch");
                        }

                        this.mode = TlsMode.SERVER;
                        // TODO: Speed up this?
                        this.availableCiphers = TlsCipher.cipherValues()
                                .stream()
                                .filter(cipher -> cipher.versions().contains(localConfig.version()))
                                .collect(Collectors.toUnmodifiableMap(TlsCipher::id, Function.identity(), (element, _) -> element));
                        this.availableCompressions = TlsCompression.compressionValues()
                                .stream()
                                .collect(Collectors.toUnmodifiableMap(TlsCompression::id, Function.identity(), (element, _) -> element));
                    }
                    case REMOTE -> {
                        this.remoteRandomData = serverHelloMessage.randomData();
                        this.remoteSessionId = serverHelloMessage.sessionId();
                        this.negotiatedCipher = availableCiphers.get(serverHelloMessage.cipher());
                        if(negotiatedCipher == null) {
                            throw new TlsException("Unknown cipher");
                        }
                        this.negotiatedCompression = availableCompressions.get(serverHelloMessage.compression());
                        if(negotiatedCompression == null) {
                            throw new TlsException("Unknown compression");
                        }
                        this.handshakeHash = TlsHandshakeHash.of(localConfig.version(), negotiatedCipher.hashFactory());
                    }
                }
            }

            case HelloDoneMessage.Server _ -> {
                switch (message.source()) {
                    case LOCAL -> this.localHelloDone = true;
                    case REMOTE -> this.remoteHelloDone = true;
                }
            }

            case CertificateMessage.Server certificateMessage -> {
                var certificates = switch (mode) {
                    case SERVER -> this.localCertificates = certificateMessage.certificates();
                    case CLIENT -> this.remoteCertificates = certificateMessage.certificates();
                };
                var source = switch (mode) {
                    case CLIENT -> TlsSource.REMOTE;
                    case SERVER -> TlsSource.LOCAL;
                };
                this.remotePublicKey = localConfig.certificatesHandler()
                        .validate(certificates, source, this)
                        .getPublicKey();
                if(negotiatedCipher.keyExchangeFactory().type() == TlsKeyExchangeType.STATIC) {
                    this.localKeyExchange = negotiatedCipher.keyExchangeFactory()
                            .newLocalKeyExchange(this);
                }
            }

            case CertificateRequestMessage.Server serverMessage -> {
                this.certificateRequestMessage = serverMessage;
            }

            case KeyExchangeMessage.Server serverKeyExchangeMessage -> {
                this.remoteKeyExchange = serverKeyExchangeMessage.parameters();
                if(negotiatedCipher.keyExchangeFactory().type() != TlsKeyExchangeType.EPHEMERAL) {
                    throw new TlsException("Unexpected server key exchange message for static key exchange");
                }

                this.localKeyExchange = negotiatedCipher.keyExchangeFactory()
                        .newLocalKeyExchange(this);
            }

            case FinishedMessage.Client _,  FinishedMessage.Server _ -> {
                // TODO: Validate
                switch (message.source()) {
                    case LOCAL -> this.localHandshakeComplete = true;
                    case REMOTE -> this.remoteHandshakeComplete = true;
                }
            }

            case KeyExchangeMessage.Client client -> {
                generatePreMasterSecret(client);
                initSession();
            }

            case CertificateMessage.Client certificateMessage -> {
                var certificates = switch (mode) {
                    case SERVER -> this.remoteCertificates = certificateMessage.certificates();
                    case CLIENT -> this.localCertificates = certificateMessage.certificates();
                };
                var source = switch (mode) {
                    case CLIENT -> TlsSource.LOCAL;
                    case SERVER -> TlsSource.REMOTE;
                };
                localConfig.certificatesHandler()
                        .validate(certificates, source, this);
            }

            case ApplicationDataMessage applicationDataMessage -> {
                if(message.source() == TlsSource.REMOTE) {
                    bufferedMessages.add(applicationDataMessage.message());
                }
            }

            case AlertMessage alertMessage -> {
                if(alertMessage.alertType() == AlertMessage.AlertType.CLOSE_NOTIFY) {
                    return false;
                }
                throw new TlsException("Received alert: " + alertMessage);
            }

            case ChangeCipherSpecMessage.Client _, ChangeCipherSpecMessage.Server _ -> {
                switch (message.source()) {
                    case LOCAL -> this.localCipherEnabled = true;
                    case REMOTE -> this.remoteCipherEnabled = true;
                }
            }

            default -> {}
        }
        return true;
    }

    private void generatePreMasterSecret(KeyExchangeMessage.Client client) {
        if(preMasterSecret != null) {
            return;
        }

        this.preMasterSecret = client.localParameters()
                .orElseThrow()
                .preMasterSecretGenerator()
                .generatePreMasterSecret(this);
    }

    public void setPreMasterSecret(byte[] key) {
        this.preMasterSecret = key;
    }

    public boolean isLocalHelloDone() {
        return localHelloDone;
    }

    public boolean isRemoteHelloDone() {
        return remoteHelloDone;
    }

    public boolean isLocalHandshakeComplete() {
        return localHandshakeComplete;
    }

    public boolean isRemoteHandshakeComplete() {
        return remoteHandshakeComplete;
    }

    public boolean isHandshakeComplete() {
        return localHandshakeComplete && remoteHandshakeComplete;
    }

    public boolean isLocalCipherEnabled() {
        return localHandshakeComplete && localCipherEnabled;
    }

    public boolean isRemoteCipherEnabled() {
        return remoteCipherEnabled;
    }

    public byte[] localRandomData() {
        return localRandomData;
    }

    public byte[] localSessionId() {
        return localSessionId;
    }

    public Optional<InetSocketAddress> remoteAddress() {
        return Optional.ofNullable(remoteAddress);
    }

    public Optional<KeyPair> localKeyPair() {
        return Optional.ofNullable(localKeyPair);
    }

    public Optional<byte[]> localCookie() {
        return Optional.ofNullable(dtlsCookie);
    }

    public void setLocalSupportedGroups(List<TlsSupportedGroup> localSupportedGroups) {
        this.localSupportedGroups = localSupportedGroups;
        TlsSupportedCurve curve = null;
        TlsSupportedFiniteField field = null;
        lookup: {
            for(var group : localSupportedGroups) {
                switch (group) {
                    case TlsSupportedCurve currentCurve -> {
                        if (curve == null) {
                            curve = currentCurve;
                        }else if(field != null) {
                            break lookup;
                        }
                    }
                    case TlsSupportedFiniteField currentField -> {
                        if (field == null) {
                            field = currentField;
                        }else if(curve != null) {
                            break lookup;
                        }
                    }
                }
            }
        }
        localPreferredEllipticCurve = curve;
        localPreferredFiniteField = field;
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
        var dependenciesTree = new LinkedHashMap<Integer, TlsExtension>();
        for (var extension : localConfig.extensions()) {
            if (extension.versions().contains(localConfig.version())) {
                var conflict = dependenciesTree.put(extension.extensionType(), extension);
                if (conflict != null) {
                    throw new IllegalArgumentException("Extension with type %s defined by <%s> conflicts with an extension processed previously with type %s defined by <%s>".formatted(
                            extension.extensionType(),
                            extension.getClass().getName(),
                            extension.extensionType(),
                            conflict.getClass().getName()
                    ));
                }
            }
        }

        this.localProcessedExtensions = new ArrayList<>(dependenciesTree.size());
        var deferred = new ArrayList<TlsExtension.Configurable>();
        while (!dependenciesTree.isEmpty()) {
            var extension = dependenciesTree.pollFirstEntry().getValue();
            switch (extension) {
                case TlsExtension.Concrete concrete -> {
                    localProcessedExtensions.add(concrete);
                    localProcessedExtensionsLength += concrete.extensionLength();
                }

                case TlsExtension.Configurable configurableExtension -> {
                    switch (configurableExtension.dependencies()) {
                        case TlsExtension.Configurable.Dependencies.None _ -> {
                            var result = configurableExtension.newInstance(this);
                            result.ifPresent(concrete -> {
                                localProcessedExtensions.add(concrete);
                                localProcessedExtensionsLength += concrete.extensionLength();
                            });
                        }

                        case TlsExtension.Configurable.Dependencies.Some some -> {
                            var conflict = false;
                            for(var dependency : some.includedTypes()) {
                                if(dependenciesTree.containsKey(dependency)) {
                                    conflict = true;
                                    break;
                                }
                            }
                            if(conflict) {
                                continue;
                            }

                            var result = configurableExtension.newInstance(this);
                            result.ifPresent(concrete -> {
                                localProcessedExtensions.add(concrete);
                                localProcessedExtensionsLength += concrete.extensionLength();
                            });
                        }

                        case TlsExtension.Configurable.Dependencies.All _ -> deferred.add(configurableExtension);
                    }
                }
            }
        }

        for(var configurableExtension : deferred) {
            var result = configurableExtension.newInstance(this);
            result.ifPresent(concrete -> {
                localProcessedExtensions.add(concrete);
                localProcessedExtensionsLength += concrete.extensionLength();
            });
        }
    }

    public Optional<TlsKeyExchange> localKeyExchange() {
        return Optional.ofNullable(localKeyExchange);
    }

    public Optional<TlsKeyExchange> remoteKeyExchange() {
        return Optional.ofNullable(remoteKeyExchange);
    }

    private void initSession() {
        this.localMasterSecretKey = TlsMasterSecret.of(
                mode,
                localConfig.version(),
                negotiatedCipher,
                preMasterSecret,
                extendedMasterSecret ? handshakeHash().orElse(null) : null,
                localRandomData,
                remoteRandomData
        );
        System.out.println("Master secret: " + Arrays.toString(localMasterSecretKey.data()));
        var clientRandom = switch (mode) {
            case CLIENT -> localRandomData;
            case SERVER -> remoteRandomData;
        };
        var serverRandom = switch (mode) {
            case SERVER -> localRandomData;
            case CLIENT -> remoteRandomData;
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

        // If I understand correctly the MAC isn't used for AEAD ciphers as the cipher concatenates the tag to the message

        var macLength = localCipher.isAEAD() ? 0 : negotiatedCipher.hashFactory().length();
        var expandedKeyLength = localCipherEngine.exportedKeyLength();
        var keyLength = localCipherEngine.keyLength();

        var ivLength = switch (localCipher) {
            case TlsCipherMode.Block block -> {
                if (block.isAEAD()) {
                    yield localCipher.ivLength();
                }

                if(localConfig.version().id().value() >= TlsVersion.TLS11.id().value()) {
                    yield 0;
                }

                yield localCipher.ivLength();
            }
            case TlsCipherMode.Stream _ -> localCipher.ivLength();
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

        var localAuthenticator = TlsExchangeMac.of(
                localConfig.version(),
                localMacKey == null ? null : negotiatedCipher.hashFactory(),
                localMacKey
        );
        var remoteAuthenticator = TlsExchangeMac.of(
                localConfig.version(),
                remoteMacKey == null ? null : negotiatedCipher.hashFactory(),
                remoteMacKey
        );

        if (keyLength == 0) {
            localCipherMode.init(true, null, null, null);
            remoteCipherMode.init(false, null, null, null);
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

            System.out.println("""
            ______________________________
            Client mac: %s
            Server mac: %s
            Client IV: %s
            Server IV: %s
            Client Key: %s
            Server Key: %s
            ______________________________
            """.formatted(
                    clientMacKey == null ? "none" : Arrays.toString(clientMacKey),
                    serverMacKey == null ? "none" : Arrays.toString(serverMacKey),
                    clientIv == null ? "none" : Arrays.toString(clientIv),
                    serverIv == null ? "none" : Arrays.toString(serverIv),
                    clientKey == null ? "none" : Arrays.toString(clientKey),
                    serverKey == null ? "none" : Arrays.toString(serverKey)
            ));
            localCipherMode.init(true, localKey, localIv, localAuthenticator);
            remoteCipherMode.init(false, remoteKey, remoteIv, remoteAuthenticator);
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

                if (ivLength == 0) {
                    localCipherMode.init(true, localKey, new byte[0], localAuthenticator);
                    remoteCipherMode.init(false, remoteKey, new byte[0], remoteAuthenticator);
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
                    localCipherMode.init(true, localKey, localIv, localAuthenticator);
                    remoteCipherMode.init(false, remoteKey, remoteIv, remoteAuthenticator);
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

                if (ivLength == 0) {
                    localCipherMode.init(true, localKey, new byte[0], localAuthenticator);
                    remoteCipherMode.init(false, remoteKey, new byte[0], remoteAuthenticator);
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

                    localCipherMode.init(true, localKey, localIv, localAuthenticator);
                    remoteCipherMode.init(false, remoteKey, remoteIv, remoteAuthenticator);
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

    public Optional<TlsMasterSecret> masterSecretKey() {
        return Optional.ofNullable(localMasterSecretKey);
    }

    public Optional<PublicKey> remotePublicKey() {
        return Optional.ofNullable(remotePublicKey);
    }

    public void setLocalKeyPair(KeyPair keyPair) {
        this.localKeyPair = keyPair;
    }

    public TlsContext setLocalKeyExchange(TlsKeyExchange localKeyExchange) {
        this.localKeyExchange = localKeyExchange;
        return this;
    }

    public Optional<TlsSupportedFiniteField> localPreferredFiniteField() {
        return Optional.ofNullable(localPreferredFiniteField);
    }

    public Optional<TlsSupportedCurve> localPreferredEllipticCurve() {
        return Optional.ofNullable(localPreferredEllipticCurve);
    }

    public List<TlsSupportedGroup> localSupportedGroups() {
        return localSupportedGroups;
    }

    public List<X509Certificate> remoteCertificates() {
        if(remoteCertificates == null) {
            return List.of();
        }else {
            return remoteCertificates;
        }
    }

    public List<X509Certificate> localCertificates() {
        if(localCertificates == null) {
            return List.of();
        }else {
            return localCertificates;
        }
    }

    public boolean hasServerCertificateRequest() {
        return certificateRequestMessage != null;
    }
}
