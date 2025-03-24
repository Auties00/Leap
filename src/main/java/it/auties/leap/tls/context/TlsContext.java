package it.auties.leap.tls.context;

import it.auties.leap.socket.SocketProtocol;
import it.auties.leap.tls.certificate.TlsCertificatesHandler;
import it.auties.leap.tls.certificate.TlsCertificatesProvider;
import it.auties.leap.tls.cipher.TlsCipher;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchange;
import it.auties.leap.tls.cipher.mode.TlsCipherMode;
import it.auties.leap.tls.compression.TlsCompression;
import it.auties.leap.tls.exception.TlsException;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.hash.TlsHash;
import it.auties.leap.tls.hash.TlsHashFactory;
import it.auties.leap.tls.hash.TlsPRF;
import it.auties.leap.tls.mac.TlsExchangeMac;
import it.auties.leap.tls.message.TlsMessageDeserializer;
import it.auties.leap.tls.property.TlsProperty;
import it.auties.leap.tls.secret.TlsMasterSecret;
import it.auties.leap.tls.util.TlsKeyUtils;
import it.auties.leap.tls.version.TlsVersion;

import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.*;

import static it.auties.leap.tls.util.BufferUtils.readBytes;
import static it.auties.leap.tls.util.TlsKeyUtils.*;

public class TlsContext {
    private final SocketProtocol protocol;
    private final List<TlsVersion> versions;
    private final List<TlsCipher> ciphers;
    private final List<TlsExtension> extensions;
    private final List<TlsCompression> compressions;
    private final TlsCertificatesProvider certificatesProvider;
    private final TlsCertificatesHandler certificatesHandler;
    private final KeyStore trustedKeyStore;
    private final TlsMessageDeserializer messageDeserializer;
    private final byte[] localRandomData;
    private final byte[] localSessionId;
    private final byte[] dtlsCookie;

    private volatile TlsMode mode;

    private volatile PublicKey remotePublicKey;
    private volatile List<X509Certificate> localCertificates;
    private volatile byte[] remoteRandomData;
    private volatile byte[] remoteSessionId;
    private volatile InetSocketAddress remoteAddress;
    private volatile TlsCipherMode remoteCipher;
    private volatile TlsKeyExchange remoteKeyExchange;

    private volatile PublicKey localPublicKey;
    private volatile List<X509Certificate> remoteCertificates;
    private volatile KeyPair localKeyPair;
    private volatile TlsCipherMode localCipher;
    private volatile TlsMasterSecret localMasterSecretKey;
    private volatile TlsKeyExchange localKeyExchange;

    private final Map<TlsProperty<?>, List<Object>> negotiableProperties;
    private final Map<TlsProperty<?>, List<Object>> negotiatedProperties;
    private final Map<TlsProperty<?>, List<Object>> properties;

    TlsContext(SocketProtocol protocol, List<TlsVersion> versions, List<TlsCipher> ciphers, List<TlsExtension> extensions, List<TlsCompression> compressions, TlsCertificatesProvider certificatesProvider, TlsCertificatesHandler certificatesHandler, KeyStore trustedKeyStore, TlsMessageDeserializer messageDeserializer, byte[] localRandomData, byte[] localSessionId) {
        this.protocol = protocol;
        this.versions = versions;
        this.ciphers = ciphers;
        this.extensions = extensions;
        this.compressions = compressions;
        this.certificatesProvider = certificatesProvider;
        this.certificatesHandler = certificatesHandler;
        this.trustedKeyStore = trustedKeyStore;
        this.messageDeserializer = messageDeserializer;
        this.localRandomData = localRandomData;
        this.localSessionId = localSessionId;
        this.dtlsCookie = switch (protocol) {
            case TCP -> null;
            case UDP -> TlsKeyUtils.randomData();
        };
        this.negotiableProperties = new HashMap<>();
        this.negotiatedProperties = new HashMap<>();
        this.properties = new HashMap<>();
    }

    public KeyStore trustedKeyStore() {
        return trustedKeyStore;
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

    public List<TlsExtension.Concrete> processedExtensions() {
        var dependenciesTree = new LinkedHashMap<Integer, TlsExtension>();
        for (var extension : extensions) {
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

        var result = new ArrayList<TlsExtension.Concrete>(dependenciesTree.size());
        var deferred = new ArrayList<TlsExtension.Configurable>();
        while (!dependenciesTree.isEmpty()) {
            var entry = dependenciesTree.pollFirstEntry();
            var extension = entry.getValue();
            switch (extension) {
                case TlsExtension.Concrete concrete -> result.add(concrete);
                case TlsExtension.Configurable configurableExtension -> {
                    switch (configurableExtension.dependencies()) {
                        case TlsExtension.Configurable.Dependencies.None _ -> configurableExtension.newInstance(this)
                                .ifPresent(result::add);

                        case TlsExtension.Configurable.Dependencies.Some some -> {
                            var conflict = false;
                            for(var dependency : some.includedTypes()) {
                                if(dependenciesTree.containsKey(dependency)) {
                                    conflict = true;
                                    break;
                                }
                            }
                            if(conflict) {
                                dependenciesTree.put(entry.getKey(), entry.getValue());
                            }else {
                                configurableExtension.newInstance(this)
                                        .ifPresent(result::add);
                            }
                        }

                        case TlsExtension.Configurable.Dependencies.All _ -> deferred.add(configurableExtension);
                    }
                }
            }
        }

        for(var configurableExtension : deferred) {
            configurableExtension.newInstance(this)
                    .ifPresent(result::add);
        }

        return result;
    }

    public Optional<TlsKeyExchange> localKeyExchange() {
        return Optional.ofNullable(localKeyExchange);
    }

    public Optional<TlsKeyExchange> remoteKeyExchange() {
        return Optional.ofNullable(remoteKeyExchange );
    }

    public void initSession(TlsKeyExchange exchange, byte[] preMasterSecret, byte[] handshakeHash) {
        if(exchange == null) {
            throw new TlsException("Invalid local key exchange");
        }

        if(preMasterSecret == null) {
            preMasterSecret = exchange.preMasterSecretGenerator()
                    .generatePreMasterSecret(this);
        }
        
        this.localMasterSecretKey = TlsMasterSecret.of(
                mode,
                negotiatedVersion,
                negotiatedCipher,
                preMasterSecret,
                extendedMasterSecret ? handshakeHash : null,
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

            System.out.printf(
                    """
                            ______________________________
                            Client mac: %s
                            Server mac: %s
                            Client IV: %s
                            Server IV: %s
                            Client Key: %s
                            Server Key: %s
                            ______________________________
                            %n""", clientMacKey == null ? "none" : Arrays.toString(clientMacKey),
                    serverMacKey == null ? "none" : Arrays.toString(serverMacKey),
                    clientIv == null ? "none" : Arrays.toString(clientIv),
                    serverIv == null ? "none" : Arrays.toString(serverIv),
                    Arrays.toString(clientKey),
                    Arrays.toString(serverKey)
            );
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

    public TlsContext setSelectedMode(TlsMode mode) {
        this.mode = mode;
        return this;
    }

    public TlsContext setRemoteCertificates(List<X509Certificate> remoteCertificates) {
        var certificate = certificatesHandler.validateChain(remoteCertificates, TlsSource.REMOTE, this);
        this.remotePublicKey = certificate == null ? null : certificate.getPublicKey();
        this.remoteCertificates = remoteCertificates;
        return this;
    }

    public TlsContext setLocalCertificates(List<X509Certificate> localCertificates) {
        var certificate = certificatesHandler.validateChain(remoteCertificates, TlsSource.LOCAL, this);
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
}
