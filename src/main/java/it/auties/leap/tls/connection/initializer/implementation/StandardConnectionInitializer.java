package it.auties.leap.tls.connection.initializer.implementation;

import it.auties.leap.tls.TlsContext;
import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.cipher.mode.TlsCipherMode;
import it.auties.leap.tls.connection.initializer.TlsConnectionInitializer;
import it.auties.leap.tls.hash.TlsHash;
import it.auties.leap.tls.hash.TlsHashFactory;
import it.auties.leap.tls.hash.TlsPRF;
import it.auties.leap.tls.mac.TlsExchangeMac;
import it.auties.leap.tls.property.TlsProperty;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;
import java.util.Arrays;

import static it.auties.leap.tls.util.BufferUtils.readBytes;
import static it.auties.leap.tls.util.TlsKeyUtils.*;
import static it.auties.leap.tls.util.TlsKeyUtils.LABEL_KEY_EXPANSION;

public final class StandardConnectionInitializer implements TlsConnectionInitializer {
    private static final StandardConnectionInitializer INSTANCE = new StandardConnectionInitializer();

    private StandardConnectionInitializer() {

    }

    public static StandardConnectionInitializer instance() {
        return INSTANCE;
    }

    @Override
    public void initialize(TlsContext context) {
        var mode = context.selectedMode()
                .orElseThrow(TlsAlert::noModeSelected);

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

        var localMasterSecretKey = context.masterSecretGenerator()
                .generateMasterSecret(context);

        System.out.println("Master secret: " + Arrays.toString(localMasterSecretKey));

        var localCipherEngine = negotiatedCipher.engineFactory()
                .newCipherEngine();
        var localCipher = negotiatedCipher.modeFactory()
                .newCipherMode(localCipherEngine);

        var remoteCipherEngine = negotiatedCipher.engineFactory()
                .newCipherEngine();
        var remoteCipher = negotiatedCipher.modeFactory()
                .newCipherMode(remoteCipherEngine);

        localConnectionState.setCipher(localCipher);
        remoteConnectionState.setCipher(remoteCipher);

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
        var keyBlock = generateBlock(negotiatedVersion, negotiatedCipher.hashFactory(), localMasterSecretKey, clientRandom, serverRandom, keyBlockLen);

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
            localCipher.init(true, null, null, null);
            remoteCipher.init(false, null, null, null);
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
            localCipher.init(true, localKey, localIv, localAuthenticator);
            remoteCipher.init(false, remoteKey, remoteIv, remoteAuthenticator);
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
                    localCipher.init(true, localKey, new byte[0], localAuthenticator);
                    remoteCipher.init(false, remoteKey, new byte[0], remoteAuthenticator);
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
                    localCipher.init(true, localKey, localIv, localAuthenticator);
                    remoteCipher.init(false, remoteKey, remoteIv, remoteAuthenticator);
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
                    localCipher.init(true, localKey, new byte[0], localAuthenticator);
                    remoteCipher.init(false, remoteKey, new byte[0], remoteAuthenticator);
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

                    localCipher.init(true, localKey, localIv, localAuthenticator);
                    remoteCipher.init(false, remoteKey, remoteIv, remoteAuthenticator);
                }
            }

            default -> throw new TlsAlert("TLS 1.1+ should not be negotiating exportable ciphersuites");
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
}
