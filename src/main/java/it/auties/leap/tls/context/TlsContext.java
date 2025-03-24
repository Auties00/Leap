package it.auties.leap.tls.context;

import it.auties.leap.tls.cipher.TlsCipher;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchange;
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
import it.auties.leap.tls.secret.TlsMasterSecret;
import it.auties.leap.tls.util.TlsKeyUtils;
import it.auties.leap.tls.version.TlsVersion;

import java.io.ByteArrayOutputStream;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.function.Function;
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

    private volatile TlsKeyExchange localKeyExchange;
    private volatile TlsKeyExchange remoteKeyExchange;

    private volatile KeyPair localKeyPair;

    private volatile byte[] dtlsCookie;

    private volatile List<TlsSupportedGroup> localSupportedGroups;
    private volatile TlsSupportedCurve localPreferredEllipticCurve;
    private volatile TlsSupportedFiniteField localPreferredFiniteField;
    private volatile boolean extendedMasterSecret;
    
    private final Queue<ByteBuffer> bufferedMessages;

    private volatile Map<Integer, TlsCipher> negotiableCiphers;
    private volatile Map<Byte, TlsCompression> negotiableCompressions;
    private List<TlsExtension.Concrete> localProcessedExtensions;
    private int localProcessedExtensionsLength;
    private PublicKey localPublicKey;
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
    
    private final LinkedHashSet<Integer> localHandshakeMessages;
    private final LinkedHashSet<Integer> remoteHandshakeMessages;

    private volatile TlsVersion negotiatedVersion;

    private volatile List<String> negotiableProtocols;

    public TlsContext(InetSocketAddress address, TlsConfig config) {
        this.remoteAddress = address;
        this.localConfig = config;
        this.localRandomData = TlsKeyUtils.randomData();
        this.localSessionId = TlsKeyUtils.randomData();
        this.dtlsCookie = switch (config.protocol()) {
            case TCP -> null;
            case UDP -> TlsKeyUtils.randomData();
        };
        this.messageDigestBuffer = new ByteArrayOutputStream(); // TODO: Calculate optimal space
        this.bufferedMessages = new LinkedList<>();
        this.localHandshakeMessages = new LinkedHashSet<>();
        this.remoteHandshakeMessages = new LinkedHashSet<>();
        this.negotiableCiphers = config.ciphers()
                .stream()
                .collect(Collectors.toUnmodifiableMap(TlsCipher::id, Function.identity()));
        this.negotiableCompressions = config.compressions()
                .stream()
                .collect(Collectors.toUnmodifiableMap(TlsCompression::id, Function.identity()));
        setLocalSupportedGroups(SupportedGroupsExtension.Configurable.recommendedGroups());
    }

    public KeyStore trustedKeyStore() {
        return localConfig.trustedKeyStore();
    }

    public Optional<TlsCipher> negotiatedCipher() {
        return Optional.ofNullable(negotiatedCipher);
    }

    public Optional<TlsMode> selectedMode() {
        return Optional.ofNullable(mode);
    }

    public TlsContext setRemoteRandomData(byte[] remoteRandomData) {
        this.remoteRandomData = remoteRandomData;
        return this;
    }

    public TlsContext setRemoteSessionId(byte[] remoteSessionId) {
        this.remoteSessionId = remoteSessionId;
        return this;
    }

    public TlsContext setNegotiatedCipher(TlsCipher negotiatedCipher) {
        this.negotiatedCipher = negotiatedCipher;
        return this;
    }

    public TlsContext setNegotiatedCompression(TlsCompression negotiatedCompression) {
        this.negotiatedCompression = negotiatedCompression;
        return this;
    }

    public TlsContext setHandshakeHash(TlsHandshakeHash handshakeHash) {
        this.handshakeHash = handshakeHash;
        return this;
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
        this.localPreferredEllipticCurve = null;
        this.localPreferredFiniteField = null;
        loop: {
            for (var group : localSupportedGroups) {
                switch (group) {
                    case TlsSupportedCurve currentCurve -> {
                        if (localPreferredEllipticCurve == null) {
                            localPreferredEllipticCurve = currentCurve;
                        }

                        if (localPreferredFiniteField != null) {
                            break loop;
                        }
                    }
                    case TlsSupportedFiniteField currentField -> {
                        if (localPreferredFiniteField == null) {
                            localPreferredFiniteField = currentField;
                        }

                        if (localPreferredEllipticCurve != null) {
                            break loop;
                        }
                    }
                }
            }
        }
    }


    public TlsContext setExtendedMasterSecret(boolean extendedMasterSecret) {
        this.extendedMasterSecret = extendedMasterSecret;
        return this;
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
            if (negotiableVersions().stream().anyMatch(version -> extension.versions().contains(version))) {
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
        return Optional.ofNullable(remoteKeyExchange );
    }

    public void initSession(TlsKeyExchange exchange) {
        if(exchange == null) {
            throw new TlsException("Invalid local key exchange");
        }

        if(preMasterSecret == null) {
            this.preMasterSecret = exchange.preMasterSecretGenerator()
                    .generatePreMasterSecret(this);
        }
        
        this.localMasterSecretKey = TlsMasterSecret.of(
                mode,
                negotiatedVersion,
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

                if(negotiatedVersion.id().value() >= TlsVersion.TLS11.id().value()) {
                    yield 0;
                }

                yield localCipher.ivLength();
            }
            case TlsCipherMode.Stream _ -> localCipher.ivLength();
        };

        var keyBlockLen = (macLength + keyLength + (expandedKeyLength.isPresent() ? 0 : ivLength)) * 2;
        var keyBlock = generateBlock(negotiatedVersion, negotiatedCipher.hashFactory(), localMasterSecretKey.data(), clientRandom, serverRandom, keyBlockLen);

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
                negotiatedVersion,
                localMacKey == null ? null : negotiatedCipher.hashFactory(),
                localMacKey
        );
        var remoteAuthenticator = TlsExchangeMac.of(
                negotiatedVersion,
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

        switch (negotiatedVersion) {
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

    public Optional<TlsVersion> negotiatedVersion() {
        return Optional.ofNullable(negotiatedVersion);
    }

    public TlsContext setNegotiatedVersion(TlsVersion negotiatedVersion) {
        this.negotiatedVersion = negotiatedVersion;
        return this;
    }

    public TlsContext setSelectedMode(TlsMode mode) {
        this.mode = mode;
        return this;
    }

    public List<TlsVersion> negotiableVersions() {
        return localConfig.versions();
    }

    public List<TlsExtension> negotiableExtensions() {
        return localConfig.extensions();
    }
    
    public void addLocalHandshakeMessage(int type) {
        var update = new TlsContextUpdate.HandshakeMessage(type, TlsSource.LOCAL);
        localConfig.contextUpdateHandler()
                .assertValid(this, update);
        localHandshakeMessages.add(type);
    }

    public SequencedSet<Integer> localHandshakeMessages() {
        return Collections.unmodifiableSequencedSet(localHandshakeMessages);
    }

    public void addRemoteHandshakeMessage(int type) {
        var update = new TlsContextUpdate.HandshakeMessage(type, TlsSource.REMOTE);
        localConfig.contextUpdateHandler()
                .assertValid(this, update);
        remoteHandshakeMessages.add(type);
    }

    public SequencedSet<Integer> remoteHandshakeMessages() {
        return Collections.unmodifiableSequencedSet(remoteHandshakeMessages);
    }

    public Collection<TlsCipher> negotiableCiphers() {
        return negotiableCiphers == null ? localConfig.ciphers() : negotiableCiphers.values();
    }

    public Optional<TlsCipher> getNegotiableCipher(int type) {
        return Optional.ofNullable(negotiableCiphers.get(type));
    }

    public Collection<TlsCompression> negotiableCompressions() {
        return negotiableCompressions == null ? localConfig.compressions() : negotiableCompressions.values();
    }

    public Optional<TlsCompression> getNegotiableCompression(byte type) {
        return Optional.ofNullable(negotiableCompressions.get(type));
    }

    public TlsContext setRemoteCertificates(List<X509Certificate> remoteCertificates) {
        var certificate = localConfig.certificatesHandler()
                .validateChain(remoteCertificates, TlsSource.REMOTE, this);
        this.remotePublicKey = certificate == null ? null : certificate.getPublicKey();
        this.remoteCertificates = remoteCertificates;
        return this;
    }

    public TlsContext setLocalCertificates(List<X509Certificate> localCertificates) {
        var certificate = localConfig.certificatesHandler()
                .validateChain(remoteCertificates, TlsSource.LOCAL, this);
        this.localPublicKey = certificate == null ? null : certificate.getPublicKey();
        this.localCertificates = localCertificates;
        return this;
    }

    public TlsContext setLocalKeyExchange(TlsKeyExchange localKeyExchange) {
        this.localKeyExchange = localKeyExchange;
        return this;
    }

    public TlsContext setRemoteKeyExchange(TlsKeyExchange remoteKeyExchange) {
        this.remoteKeyExchange = remoteKeyExchange;
        return this;
    }

    public void addMessage(ByteBuffer message) {
        bufferedMessages.add(message);
    }

    public List<String> negotiableProtocols() {
        return negotiableProtocols;
    }

    public TlsContext setNegotiableProtocols(List<String> negotiableProtocols) {
        this.negotiableProtocols = negotiableProtocols;
        return this;
    }
}
