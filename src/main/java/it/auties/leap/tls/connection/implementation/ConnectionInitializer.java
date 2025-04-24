package it.auties.leap.tls.connection.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
import it.auties.leap.tls.cipher.exchange.TlsExchangeMac;
import it.auties.leap.tls.cipher.mode.TlsCipherWithEngineFactory;
import it.auties.leap.tls.connection.TlsConnection;
import it.auties.leap.tls.connection.TlsConnectionInitializer;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.hash.TlsHashFactory;
import it.auties.leap.tls.hash.TlsPrf;
import it.auties.leap.tls.property.TlsProperty;
import it.auties.leap.tls.secret.TlsSecret;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;
import java.util.Arrays;

import static it.auties.leap.tls.util.BufferUtils.readBytes;
import static it.auties.leap.tls.util.TlsKeyUtils.*;

public final class ConnectionInitializer implements TlsConnectionInitializer {
    private static final ConnectionInitializer INSTANCE = new ConnectionInitializer();

    private ConnectionInitializer() {

    }

    public static ConnectionInitializer instance() {
        return INSTANCE;
    }

    @Override
    public void initialize(TlsContext context) {
        var negotiatedVersion = context.getNegotiatedValue(TlsProperty.version())
                .orElseThrow(() -> new TlsAlert("Missing negotiated property: version", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR));
        var negotiatedCipher = context.getNegotiatedValue(TlsProperty.cipher())
                .orElseThrow(() -> new TlsAlert("Missing negotiated property: cipher", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR));
        var cipherFactory = negotiatedCipher.cipherFactory();
        var engineFactory = negotiatedCipher.cipherEngineFactory();
        var hashFactory = negotiatedCipher.hashFactory();
        var localConnectionState = context.localConnectionState();
        var remoteConnectionState = context.remoteConnectionState()
                .orElseThrow(() -> new TlsAlert("No remote connection state was created", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR));
        var masterSecret = context.masterSecretGenerator()
                .generateMasterSecret(context);
        context.setMasterSecretKey(masterSecret);
        System.out.println("Master secret: " + Arrays.toString(masterSecret.data()));
        if(negotiatedVersion == TlsVersion.TLS13 || negotiatedVersion == TlsVersion.DTLS13) {
            var handshakeHash = context.connectionHandshakeHash().digest();

            System.out.println("Handshake hash for tls 1.3 key derivation: " + Arrays.toString(handshakeHash));
            var clientSecret = TlsSecret.of(hashFactory, "tls13 c hs traffic", handshakeHash, masterSecret.data(), hashFactory.length());
            System.out.println("Client secret for tls 1.3 key derivation: " + Arrays.toString(clientSecret.data()));
            var clientKey = TlsSecret.of(hashFactory, "tls13 key", null, clientSecret.data(), engineFactory.keyLength());
            System.out.println("Read key for tls 1.3 key derivation: " + Arrays.toString(clientKey.data()));
            var clientIv = TlsSecret.of(hashFactory, "tls13 iv", null, clientSecret.data(), cipherFactory.ivLength());
            System.out.println("Read iv for tls 1.3 key derivation: " + Arrays.toString(clientIv.data()));
            clientSecret.destroy();

            var serverSecret = TlsSecret.of(hashFactory, "tls13 s hs traffic", handshakeHash, masterSecret.data(), hashFactory.length());
            System.out.println("Server secret for tls 1.3 key derivation: " + Arrays.toString(serverSecret.data()));
            var serverKey = TlsSecret.of(hashFactory, "tls13 key", null, serverSecret.data(), engineFactory.keyLength());
            System.out.println("Write key for tls 1.3 key derivation: " + Arrays.toString(serverKey.data()));
            var serverIv = TlsSecret.of(hashFactory, "tls13 iv", null, serverSecret.data(), cipherFactory.ivLength());
            System.out.println("Write iv for tls 1.3 key derivation: " + Arrays.toString(serverIv.data()));
            serverSecret.destroy();

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

            switch (localConnectionState.type()) {
                case CLIENT -> initCiphers(
                        negotiatedVersion,
                        cipherFactory,
                        localConnectionState, clientIv, clientKey,
                        remoteConnectionState, serverIv, serverKey
                );

                case SERVER -> initCiphers(
                        negotiatedVersion,
                        cipherFactory,
                        localConnectionState, serverIv, serverKey,
                        remoteConnectionState, clientIv, clientKey
                );
            }
        }else { // TODO: Generalize this branch
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
                var localKey = switch (context.localConnectionState().type()) {
                    case CLIENT -> clientKey;
                    case SERVER -> serverKey;
                };
                var remoteKey = switch (context.localConnectionState().type()) {
                    case CLIENT -> serverKey;
                    case SERVER -> clientKey;
                };

                var clientIv = ivLength == 0 ? new byte[0] : readBytes(keyBlock, ivLength);
                var serverIv = ivLength == 0 ? new byte[0] : readBytes(keyBlock, ivLength);
                var localIv = switch (context.localConnectionState().type()) {
                    case CLIENT -> clientIv;
                    case SERVER -> serverIv;
                };
                var remoteIv = switch (context.localConnectionState().type()) {
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
                var clientKey = readBytes(keyBlock, keyLength);
                var serverKey = readBytes(keyBlock, keyLength);
                var seed = TlsPrf.seed(clientRandom, serverRandom);
                var expandedClientKey = TlsPrf.tls10Prf(clientKey, LABEL_CLIENT_WRITE_KEY, seed, expandedKeyLength.getAsInt());
                var expandedServerKey = TlsPrf.tls10Prf(serverKey, LABEL_SERVER_WRITE_KEY, seed, expandedKeyLength.getAsInt());

                var localKey = switch (context.localConnectionState().type()) {
                    case CLIENT -> expandedClientKey;
                    case SERVER -> expandedServerKey;
                };
                var remoteKey = switch (context.localConnectionState().type()) {
                    case CLIENT -> expandedServerKey;
                    case SERVER -> expandedClientKey;
                };

                if (ivLength == 0) {
                    var localCipher = cipherFactory.newCipher(true, localKey, new byte[0], localAuthenticator);
                    localConnectionState.setCipher(localCipher);
                    var remoteCipher = cipherFactory.newCipher(false, remoteKey, new byte[0], remoteAuthenticator);
                    remoteConnectionState.setCipher(remoteCipher);
                } else {
                    var block = TlsPrf.tls10Prf(null, LABEL_IV_BLOCK, seed, ivLength << 1);
                    var clientIv = Arrays.copyOf(block, ivLength);
                    var serverIv = Arrays.copyOfRange(block, ivLength, ivLength << 2);

                    var localIv = switch (context.localConnectionState().type()) {
                        case CLIENT -> clientIv;
                        case SERVER -> serverIv;
                    };
                    var remoteIv = switch (context.localConnectionState().type()) {
                        case CLIENT -> serverIv;
                        case SERVER -> clientIv;
                    };
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

    private void initCiphers(
            TlsVersion version,
            TlsCipherWithEngineFactory cipherFactory,
            TlsConnection localState, TlsSecret localIv, TlsSecret localKey,
            TlsConnection remoteState, TlsSecret remoteIv, TlsSecret remoteKey
    ) {
        var localAuthenticator = TlsExchangeMac.of(version, null, null);
        var localCipher = cipherFactory.newCipher(true, localKey.data(), localIv.data(), localAuthenticator);
        localState.setCipher(localCipher);
        var remoteAuthenticator = TlsExchangeMac.of(version, null, null);
        var remoteCipher = cipherFactory.newCipher(false, remoteKey.data(), remoteIv.data(), remoteAuthenticator);
        remoteState.setCipher(remoteCipher);
    }

    private static ByteBuffer generateBlock(TlsVersion version, TlsHashFactory hashFactory, byte[] masterSecret, byte[] clientRandom, byte[] serverRandom, int keyBlockLen) {
        return switch (version) {
            case TLS10, TLS11 -> {
                var seed = TlsPrf.seed(serverRandom, clientRandom);
                var result = TlsPrf.tls10Prf(
                        masterSecret,
                        LABEL_KEY_EXPANSION,
                        seed,
                        keyBlockLen
                );
                yield ByteBuffer.wrap(result);
            }
            default -> {
                var seed = TlsPrf.seed(serverRandom, clientRandom);
                var result = TlsPrf.tls12Prf(
                        masterSecret,
                        LABEL_KEY_EXPANSION,
                        seed,
                        keyBlockLen,
                        hashFactory.newHash()
                );
                yield ByteBuffer.wrap(result);
            }
        };
    }
}
