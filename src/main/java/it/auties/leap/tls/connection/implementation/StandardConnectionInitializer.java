package it.auties.leap.tls.connection.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.cipher.exchange.TlsExchangeMac;
import it.auties.leap.tls.connection.TlsConnectionInitializer;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.hash.TlsHashFactory;
import it.auties.leap.tls.hash.TlsPRF;
import it.auties.leap.tls.property.TlsProperty;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;
import java.util.Arrays;

import static it.auties.leap.tls.util.BufferUtils.readBytes;
import static it.auties.leap.tls.util.TlsKeyUtils.*;

public final class StandardConnectionInitializer implements TlsConnectionInitializer {
    private static final StandardConnectionInitializer INSTANCE = new StandardConnectionInitializer();

    private StandardConnectionInitializer() {

    }

    public static StandardConnectionInitializer instance() {
        return INSTANCE;
    }

    @Override
    public void initialize(TlsContext context) {
        var mode = context.mode();

        var localConnectionState = context.localConnectionState();
        var remoteConnectionState = context.remoteConnectionState()
                .orElseThrow(TlsAlert::noRemoteConnectionState);

        var negotiatedVersion = context.getNegotiatedValue(TlsProperty.version())
                .orElseThrow(() -> TlsAlert.noNegotiatedProperty(TlsProperty.version()));
        var negotiatedCipher = context.getNegotiatedValue(TlsProperty.cipher())
                .orElseThrow(() -> TlsAlert.noNegotiatedProperty(TlsProperty.cipher()));
        var clientRandom = switch (mode) {
            case CLIENT -> localConnectionState.randomData();
            case SERVER -> remoteConnectionState.randomData();
        };
        var serverRandom = switch (mode) {
            case SERVER -> localConnectionState.randomData();
            case CLIENT -> remoteConnectionState.randomData();
        };

        var masterSecret = context.masterSecretGenerator()
                .generateMasterSecret(context);
        context.setMasterSecretKey(masterSecret);

        System.out.println("Master secret: " + Arrays.toString(masterSecret.data()));

        var cipherFactory = negotiatedCipher.cipherFactory()
                .with(negotiatedCipher.cipherEngineFactory());

        var macLength = cipherFactory.aead() ? 0 : negotiatedCipher.hashFactory().length();
        var expandedKeyLength = negotiatedCipher.cipherEngineFactory()
                .exportedKeyLength();
        var keyLength = negotiatedCipher.cipherEngineFactory()
                .keyLength();

        var ivLength = cipherFactory.aead() || negotiatedVersion.id().value() < TlsVersion.TLS11.id().value() ? cipherFactory.fixedIvLength() : 0;

        var keyBlockLen = (macLength + keyLength + (expandedKeyLength.isPresent() ? 0 : ivLength)) * 2;
        var keyBlock = generateBlock(negotiatedVersion, negotiatedCipher.hashFactory(), masterSecret.data(), clientRandom, serverRandom, keyBlockLen);

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

        if (expandedKeyLength.isEmpty()) {
            var clientKey = readBytes(keyBlock, keyLength);
            var serverKey = readBytes(keyBlock, keyLength);
            var localKey = switch (mode) {
                case CLIENT -> clientKey;
                case SERVER -> serverKey;
            };
            var remoteKey = switch (mode) {
                case CLIENT -> serverKey;
                case SERVER -> clientKey;
            };

            var clientIv = ivLength == 0 ? new byte[0] : readBytes(keyBlock, ivLength);
            var serverIv = ivLength == 0 ? new byte[0] : readBytes(keyBlock, ivLength);
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
        }else if (negotiatedVersion == TlsVersion.TLS10) {
            var clientKey = readBytes(keyBlock, keyLength);
            var serverKey = readBytes(keyBlock, keyLength);
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
                var localCipher = cipherFactory.newCipher(true, localKey, new byte[0], localAuthenticator);
                localConnectionState.setCipher(localCipher);
                var remoteCipher = cipherFactory.newCipher(false, remoteKey, new byte[0], remoteAuthenticator);
                remoteConnectionState.setCipher(remoteCipher);
            } else {
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
                var localCipher = cipherFactory.newCipher(true, localKey, localIv, localAuthenticator);
                localConnectionState.setCipher(localCipher);
                var remoteCipher = cipherFactory.newCipher(false, remoteKey, remoteIv, remoteAuthenticator);
                remoteConnectionState.setCipher(remoteCipher);
            }
        } else {
            throw new TlsAlert("TLS 1.1+ should not be negotiating exportable ciphersuites");
        }
    }

    private static ByteBuffer generateBlock(TlsVersion version, TlsHashFactory hashFactory, byte[] masterSecret, byte[] clientRandom, byte[] serverRandom, int keyBlockLen) {
        return switch (version) {
            case TLS10, TLS11 -> {
                var seed = TlsPRF.seed(serverRandom, clientRandom);
                var result = TlsPRF.tls10Prf(
                        masterSecret,
                        LABEL_KEY_EXPANSION,
                        seed,
                        keyBlockLen
                );
                yield ByteBuffer.wrap(result);
            }
            default -> {
                var seed = TlsPRF.seed(serverRandom, clientRandom);
                var result = TlsPRF.tls12Prf(
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
