package it.auties.leap.tls.connection;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
import it.auties.leap.tls.ciphersuite.exchange.TlsExchangeMac;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.hash.TlsHashFactory;
import it.auties.leap.tls.hash.TlsHkdf;
import it.auties.leap.tls.hash.TlsHmac;
import it.auties.leap.tls.hash.TlsPrf;
import it.auties.leap.tls.context.TlsContextualProperty;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;
import java.util.Arrays;

import static it.auties.leap.tls.util.BufferUtils.readBytes;
import static it.auties.leap.tls.util.TlsKeyUtils.*;

public class TlsConnectionHandler {
    protected static final byte[] LABEL_MASTER_SECRET = {109, 97, 115, 116, 101, 114, 32, 115, 101, 99, 114, 101, 116};
    protected static final byte[] LABEL_EXTENDED_MASTER_SECRET = {101, 120, 116, 101, 110, 100, 101, 100, 32, 109, 97, 115, 116, 101, 114, 32, 115, 101, 99, 114, 101, 116};
    protected static final int LEGACY_TLS_SECRET_LENGTH = 48;

    private static final TlsConnectionHandler INSTANCE = new TlsConnectionHandler();

    private TlsConnectionHandler() {

    }

    public static TlsConnectionHandler instance() {
        return INSTANCE;
    }

    public TlsConnectionSecret generateMasterSecret(TlsContext context) {
        var version = context.getNegotiatedValue(TlsContextualProperty.version())
                .orElseThrow(() -> new TlsAlert("Missing negotiated property: version", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR));
        return switch (version) {
            case TLS10, TLS11, DTLS10 -> {
                var extendedMasterSecret = context.getNegotiatedValue(TlsContextualProperty.extendedMasterSecret()).orElse(false);
                var label = extendedMasterSecret ? LABEL_EXTENDED_MASTER_SECRET : LABEL_MASTER_SECRET;
                var seed = extendedMasterSecret ? getExtendedMasterSecretSeed(context) : getMasterSecretSeed(context);
                var preMasterSecret = generatePreMasterSecret(context);
                var masterSecret = TlsPrf.tls10Prf(
                        preMasterSecret.data(),
                        label,
                        seed,
                        LEGACY_TLS_SECRET_LENGTH
                );
                preMasterSecret.destroy();
                yield TlsConnectionSecret.of(masterSecret);
            }

            case TLS12, DTLS12 -> {
                var negotiatedCipher = context.getNegotiatedValue(TlsContextualProperty.cipher())
                        .orElseThrow(() -> new TlsAlert("Missing negotiated property: cipher", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR));
                var extendedMasterSecret = context.getNegotiatedValue(TlsContextualProperty.extendedMasterSecret()).orElse(false);
                var label = extendedMasterSecret ? LABEL_EXTENDED_MASTER_SECRET : LABEL_MASTER_SECRET;
                var seed = extendedMasterSecret ? getExtendedMasterSecretSeed(context) : getMasterSecretSeed(context);
                var preMasterSecret = generatePreMasterSecret(context);
                var masterSecret = TlsPrf.tls12Prf(
                        preMasterSecret.data(),
                        label,
                        seed,
                        LEGACY_TLS_SECRET_LENGTH,
                        negotiatedCipher.hashFactory().newHash()
                );
                preMasterSecret.destroy();
                yield TlsConnectionSecret.of(masterSecret);
            }

            case TLS13, DTLS13 -> {
                var sharedSecret = context.localConnectionState()
                        .ephemeralKeyPair()
                        .orElseThrow(() -> new TlsAlert("No ephemeral key pair was generated for local connection", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR))
                        .group()
                        .computeSharedSecret(context);
                System.out.println("Pre master secret: " + Arrays.toString(sharedSecret.data()));
                var cipher = context.getNegotiatedValue(TlsContextualProperty.cipher())
                        .orElseThrow(() -> new TlsAlert("Missing negotiated property: cipher", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR));
                var hashFactory = cipher.hashFactory();
                var hkdf = TlsHkdf.of(TlsHmac.of(hashFactory));
                var zeros = new byte[hashFactory.length()];
                var earlySecret = hkdf.extract(zeros, zeros);
                var saltSecretContext = hashFactory
                        .newHash()
                        .digest(false);
                var saltSecret = TlsConnectionSecret.of(hashFactory, "tls13 derived", saltSecretContext, earlySecret, hashFactory.length());
                var masterSecret = hkdf.extract(saltSecret.data(), sharedSecret.data());
                saltSecret.destroy();
                sharedSecret.destroy();
                yield TlsConnectionSecret.of(masterSecret);
            }
        };
    }

    private byte[] getMasterSecretSeed(TlsContext context) {
        var clientRandom = getClientRandom(context);
        var serverRandom = getServerRandom(context);
        return TlsPrf.seed(clientRandom, serverRandom);
    }

    private byte[] getExtendedMasterSecretSeed(TlsContext context) {
        var hash = context.connectionHandshakeHash();
        hash.commit(); // FIXME: Is this the correct way?
        return hash.digest();
    }

    protected final byte[] getServerRandom(TlsContext context) {
        return switch (context.localConnectionState().type()) {
            case CLIENT -> context.remoteConnectionState()
                    .orElseThrow(() -> new TlsAlert("No remote connection state was created", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR))
                    .randomData();
            case SERVER -> context.localConnectionState()
                    .randomData();
        };
    }

    protected final byte[] getClientRandom(TlsContext context) {
        return switch (context.localConnectionState().type()) {
            case CLIENT -> context.localConnectionState()
                    .randomData();
            case SERVER -> context.remoteConnectionState()
                    .orElseThrow(() -> new TlsAlert("No remote connection state was created", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR))
                    .randomData();
        };
    }

    protected final TlsConnectionSecret generatePreMasterSecret(TlsContext context) {
        return context.localConnectionState()
                .keyExchange()
                .orElseThrow(() -> new TlsAlert("No local key exchange", TlsAlertLevel.FATAL, TlsAlertType.ILLEGAL_PARAMETER))
                .generatePreSharedSecret(context);
    }

    public void initialize(TlsContext context) {
        var negotiatedVersion = context.getNegotiatedValue(TlsContextualProperty.version())
                .orElseThrow(() -> new TlsAlert("Missing negotiated property: version", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR));
        var negotiatedCipher = context.getNegotiatedValue(TlsContextualProperty.cipher())
                .orElseThrow(() -> new TlsAlert("Missing negotiated property: cipher", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR));
        var cipherFactory = negotiatedCipher.cipherFactory();
        var engineFactory = negotiatedCipher.cipherEngineFactory();
        var hashFactory = negotiatedCipher.hashFactory();
        var localConnectionState = context.localConnectionState();
        var remoteConnectionState = context.remoteConnectionState()
                .orElseThrow(() -> new TlsAlert("No remote connection state was created", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR));
        var masterSecret = generateMasterSecret(context);
        context.setMasterSecretKey(masterSecret);
        System.out.println("Master secret: " + Arrays.toString(masterSecret.data()));
        if(negotiatedVersion == TlsVersion.TLS13 || negotiatedVersion == TlsVersion.DTLS13) {
            var handshakeHash = context.connectionHandshakeHash().digest();
            System.out.println("Handshake hash for tls 1.3 key derivation: " + Arrays.toString(handshakeHash));

            var clientSecret = TlsConnectionSecret.of(hashFactory, "tls13 c hs traffic", handshakeHash, masterSecret.data(), hashFactory.length());
            System.out.println("Client secret for tls 1.3 key derivation: " + Arrays.toString(clientSecret.data()));
            var clientKey = TlsConnectionSecret.of(hashFactory, "tls13 key", null, clientSecret.data(), engineFactory.keyLength());
            System.out.println("Read key for tls 1.3 key derivation: " + Arrays.toString(clientKey.data()));
            var clientIv = TlsConnectionSecret.of(hashFactory, "tls13 iv", null, clientSecret.data(), cipherFactory.ivLength());
            System.out.println("Read iv for tls 1.3 key derivation: " + Arrays.toString(clientIv.data()));

            var serverSecret = TlsConnectionSecret.of(hashFactory, "tls13 s hs traffic", handshakeHash, masterSecret.data(), hashFactory.length());
            System.out.println("Server secret for tls 1.3 key derivation: " + Arrays.toString(serverSecret.data()));
            var serverKey = TlsConnectionSecret.of(hashFactory, "tls13 key", null, serverSecret.data(), engineFactory.keyLength());
            System.out.println("Write key for tls 1.3 key derivation: " + Arrays.toString(serverKey.data()));
            var serverIv = TlsConnectionSecret.of(hashFactory, "tls13 iv", null, serverSecret.data(), cipherFactory.ivLength());
            System.out.println("Write iv for tls 1.3 key derivation: " + Arrays.toString(serverIv.data()));

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
                            %n""",
                    "none",
                    "none",
                    Arrays.toString(clientIv.data()),
                    Arrays.toString(serverIv.data()),
                    Arrays.toString(clientKey.data()),
                    Arrays.toString(serverKey.data())
            );

            var localKey = getConnectionValue(localConnectionState, clientKey, serverKey);
            var localIv = getConnectionValue(localConnectionState, clientIv, serverIv);
            var localSecret = getConnectionValue(localConnectionState, clientSecret, serverSecret);
            var localAuthenticator = TlsExchangeMac.of(negotiatedVersion, null, null);
            var localCipher = cipherFactory.newCipher(true, localKey.data(), localIv.data(), localAuthenticator);
            localCipher.setEnabled(true);
            localConnectionState.setCipher(localCipher);
            localConnectionState.setHandshakeSecret(localSecret);

            var remoteKey = getConnectionValue(remoteConnectionState, clientKey, serverKey);
            var remoteIv = getConnectionValue(remoteConnectionState, clientIv, serverIv);
            var remoteSecret = getConnectionValue(remoteConnectionState, clientSecret, serverSecret);
            var remoteAuthenticator = TlsExchangeMac.of(negotiatedVersion, null, null);
            var remoteCipher = cipherFactory.newCipher(false, remoteKey.data(), remoteIv.data(), remoteAuthenticator);
            remoteCipher.setEnabled(true);
            remoteConnectionState.setCipher(remoteCipher);
            remoteConnectionState.setHandshakeSecret(remoteSecret);
        }else {
            var clientRandom = switch (context.localConnectionState().type()) {
                case CLIENT -> localConnectionState.randomData();
                case SERVER -> remoteConnectionState.randomData();
            };
            var serverRandom = switch (context.localConnectionState().type()) {
                case SERVER -> localConnectionState.randomData();
                case CLIENT -> remoteConnectionState.randomData();
            };

            var macLength = cipherFactory.aead() ? 0 : hashFactory.length();
            var expandedKeyLength = engineFactory.exportedKeyLength();
            var keyLength = engineFactory.keyLength();

            var ivLength = cipherFactory.aead() || negotiatedVersion.id().value() < TlsVersion.TLS11.id().value() ? cipherFactory.fixedIvLength() : 0;

            var keyBlockLen = (macLength + keyLength + (expandedKeyLength.isPresent() ? 0 : ivLength)) * 2;
            var keyBlock = generateBlock(negotiatedVersion, hashFactory, masterSecret.data(), clientRandom, serverRandom, keyBlockLen);

            var clientMacKey = macLength != 0 ? readBytes(keyBlock, macLength) : null;
            var serverMacKey = macLength != 0 ? readBytes(keyBlock, macLength) : null;

            var localMacKey = switch (context.localConnectionState().type()) {
                case CLIENT -> clientMacKey;
                case SERVER -> serverMacKey;
            };
            var remoteMacKey = switch (context.localConnectionState().type()) {
                case CLIENT -> serverMacKey;
                case SERVER -> clientMacKey;
            };

            var localAuthenticator = TlsExchangeMac.of(
                    negotiatedVersion,
                    localMacKey == null ? null : hashFactory,
                    localMacKey
            );
            var remoteAuthenticator = TlsExchangeMac.of(
                    negotiatedVersion,
                    remoteMacKey == null ? null : hashFactory,
                    remoteMacKey
            );

            if (expandedKeyLength.isEmpty()) {
                var clientKey = readBytes(keyBlock, keyLength);
                var serverKey = readBytes(keyBlock, keyLength);
                var localKey = getConnectionValue(localConnectionState, clientKey, serverKey);
                var remoteKey = getConnectionValue(remoteConnectionState, clientKey, serverKey);

                var clientIv = ivLength == 0 ? new byte[0] : readBytes(keyBlock, ivLength);
                var serverIv = ivLength == 0 ? new byte[0] : readBytes(keyBlock, ivLength);
                var localIv = getConnectionValue(localConnectionState, clientIv, serverIv);
                var remoteIv = getConnectionValue(remoteConnectionState, clientIv, serverIv);

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
                                %n""",
                        clientMacKey == null ? "none" : Arrays.toString(clientMacKey),
                        serverMacKey == null ? "none" : Arrays.toString(serverMacKey),
                        Arrays.toString(clientIv),
                        Arrays.toString(serverIv),
                        Arrays.toString(clientKey),
                        Arrays.toString(serverKey)
                );
                var localCipher = cipherFactory.newCipher(true, localKey, localIv, localAuthenticator);
                localConnectionState.setCipher(localCipher);
                var remoteCipher = cipherFactory.newCipher(false, remoteKey, remoteIv, remoteAuthenticator);
                remoteConnectionState.setCipher(remoteCipher);
            } else if (negotiatedVersion == TlsVersion.TLS10) {
                var exportableClientKey = readBytes(keyBlock, keyLength);
                var exportableServerKey = readBytes(keyBlock, keyLength);
                var exportableKeySeed = TlsPrf.seed(clientRandom, serverRandom);
                var expandedClientKey = TlsPrf.tls10Prf(exportableClientKey, LABEL_CLIENT_WRITE_KEY, exportableKeySeed, expandedKeyLength.getAsInt());
                var expandedServerKey = TlsPrf.tls10Prf(exportableServerKey, LABEL_SERVER_WRITE_KEY, exportableKeySeed, expandedKeyLength.getAsInt());
                var localKey = getConnectionValue(localConnectionState, expandedClientKey, expandedServerKey);
                var remoteKey = getConnectionValue(remoteConnectionState, expandedClientKey, expandedServerKey);

                if (ivLength == 0) {
                    var localCipher = cipherFactory.newCipher(true, localKey, new byte[0], localAuthenticator);
                    localConnectionState.setCipher(localCipher);
                    var remoteCipher = cipherFactory.newCipher(false, remoteKey, new byte[0], remoteAuthenticator);
                    remoteConnectionState.setCipher(remoteCipher);
                } else {
                    var block = TlsPrf.tls10Prf(null, LABEL_IV_BLOCK, exportableKeySeed, ivLength << 1);
                    var clientIv = Arrays.copyOf(block, ivLength);
                    var serverIv = Arrays.copyOfRange(block, ivLength, ivLength << 2);
                    var localIv = getConnectionValue(localConnectionState, clientIv, serverIv);
                    var remoteIv = getConnectionValue(remoteConnectionState, clientIv, serverIv);

                    var localCipher = cipherFactory.newCipher(true, localKey, localIv, localAuthenticator);
                    localConnectionState.setCipher(localCipher);
                    var remoteCipher = cipherFactory.newCipher(false, remoteKey, remoteIv, remoteAuthenticator);
                    remoteConnectionState.setCipher(remoteCipher);
                }
            } else {
                throw new TlsAlert("TLS 1.1+ should not be negotiating exportable ciphersuites", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
            }
        }
    }

    public void finalize(TlsContext context, TlsSource source) {
        var negotiatedVersion = context.getNegotiatedValue(TlsContextualProperty.version())
                .orElseThrow(() -> new TlsAlert("Missing negotiated property: version", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR));
        if (negotiatedVersion != TlsVersion.TLS13 && negotiatedVersion != TlsVersion.DTLS13) {
            return;
        }

        var negotiatedCipher = context.getNegotiatedValue(TlsContextualProperty.cipher())
                .orElseThrow(() -> new TlsAlert("Missing negotiated property: cipher", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR));
        var handshakeHash = context.connectionHandshakeHash().digest();
        var hashFactory = negotiatedCipher.hashFactory();
        var cipherFactory = negotiatedCipher.cipherFactory();
        var engineFactory = negotiatedCipher.cipherEngineFactory();
        var saltSecretContext = hashFactory.newHash()
                .digest(false);
        var saltSecret = TlsConnectionSecret.of(hashFactory, "tls13 derived", saltSecretContext, context.masterSecretKey()
                .orElseThrow().data(), hashFactory.length());

        var hkdf = TlsHkdf.of(TlsHmac.of(hashFactory));
        var zeros = new byte[hashFactory.length()];
        var masterSecret = hkdf.extract(saltSecret.data(), zeros);

        var forEncryption = source == TlsSource.LOCAL;
        var state = switch (source) {
            case LOCAL -> context.localConnectionState();
            case REMOTE -> context.remoteConnectionState()
                    .orElseThrow();
        };
        var secretLabel = switch(state.type()) {
            case CLIENT -> "tls13 c ap traffic";
            case SERVER -> "tls13 s ap traffic";
        };
        var secret = TlsConnectionSecret.of(hashFactory, secretLabel, handshakeHash, masterSecret, hashFactory.length());
        System.out.println("Server secret for tls 1.3 key derivation: " + Arrays.toString(secret.data()));
        var key = TlsConnectionSecret.of(hashFactory, "tls13 key", null, secret.data(), engineFactory.keyLength());
        System.out.println("Write key for tls 1.3 key derivation: " + Arrays.toString(key.data()));
        var iv = TlsConnectionSecret.of(hashFactory, "tls13 iv", null, secret.data(), cipherFactory.ivLength());
        System.out.println("Write iv for tls 1.3 key derivation: " + Arrays.toString(iv.data()));
        var authenticator = TlsExchangeMac.of(negotiatedVersion, null, null);
        var cipher = cipherFactory.newCipher(forEncryption, key.data(), iv.data(), authenticator);
        cipher.setEnabled(true);
        state.setCipher(cipher);
        state.setHandshakeSecret(secret);
    }

    protected final <T> T getConnectionValue(TlsConnection connection, T client, T server) {
        return switch (connection.type()) {
            case CLIENT -> client;
            case SERVER -> server;
        };
    }

    protected final ByteBuffer generateBlock(TlsVersion version, TlsHashFactory hashFactory, byte[] masterSecret, byte[] clientRandom, byte[] serverRandom, int keyBlockLen) {
        var seed = TlsPrf.seed(serverRandom, clientRandom);
        var prf = switch (version) {
            case TLS10, TLS11 -> TlsPrf.tls10Prf(
                    masterSecret,
                    LABEL_KEY_EXPANSION,
                    seed,
                    keyBlockLen
            );
            default -> TlsPrf.tls12Prf(
                    masterSecret,
                    LABEL_KEY_EXPANSION,
                    seed,
                    keyBlockLen,
                    hashFactory.newHash()
            );
        };
        return ByteBuffer.wrap(prf);
    }
}
