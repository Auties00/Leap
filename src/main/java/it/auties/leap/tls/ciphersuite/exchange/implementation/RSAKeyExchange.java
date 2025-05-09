package it.auties.leap.tls.ciphersuite.exchange.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
import it.auties.leap.tls.ciphersuite.exchange.TlsKeyExchange;
import it.auties.leap.tls.ciphersuite.exchange.TlsKeyExchangeFactory;
import it.auties.leap.tls.ciphersuite.exchange.TlsKeyExchangeType;
import it.auties.leap.tls.connection.TlsConnectionSecret;
import it.auties.leap.tls.connection.TlsConnectionType;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsContextualProperty;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;
import java.util.Optional;

import static it.auties.leap.tls.util.BufferUtils.*;

public sealed abstract class RSAKeyExchange implements TlsKeyExchange {
    private static final TlsKeyExchangeFactory STATIC_FACTORY = new TlsKeyExchangeFactory() {
        @Override
        public Optional<TlsKeyExchange> newLocalKeyExchange(TlsContext context) {
            return switch (context.localConnectionState().type()) {
                case CLIENT -> {
                    try {
                        var preMasterSecret = new byte[48];
                        SecureRandom.getInstanceStrong()
                                .nextBytes(preMasterSecret);
                        var version = context.getNegotiatedValue(TlsContextualProperty.version()).orElseThrow(() -> new TlsAlert(
                                "Cannot generate static client key exchange: no tls version was negotiated",
                                TlsAlertLevel.FATAL,
                                TlsAlertType.HANDSHAKE_FAILURE
                        ));
                        preMasterSecret[0] = version.id().minor();
                        preMasterSecret[1] = version.id().major();
                        var cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                        var remoteCertificate = context.remoteConnectionState()
                                .orElseThrow(() -> new TlsAlert(
                                        "Cannot generate static key exchange: no remote server connection state was created",
                                        TlsAlertLevel.FATAL,
                                        TlsAlertType.HANDSHAKE_FAILURE
                                ))
                                .certificates()
                                .stream()
                                .filter(entry -> entry.publicKey() instanceof RSAPublicKey)
                                .findFirst()
                                .orElseThrow(() -> new TlsAlert(
                                        "Cannot generate static key exchange: no remote RSA certificated was received",
                                        TlsAlertLevel.FATAL,
                                        TlsAlertType.HANDSHAKE_FAILURE
                                ));
                        cipher.init(Cipher.WRAP_MODE, remoteCertificate.value());
                        var encryptedPreMasterSecret = TlsConnectionSecret.of(cipher.wrap(new SecretKeySpec(preMasterSecret, "raw")));
                        var localKeyExchange = new Client(encryptedPreMasterSecret);
                        yield Optional.of(localKeyExchange);
                    }catch (GeneralSecurityException exception) {
                        throw new TlsAlert(
                                "Cannot generate RSA pre master secret: " + exception.getMessage(),
                                exception,
                                TlsAlertLevel.FATAL,
                                TlsAlertType.HANDSHAKE_FAILURE
                        );
                    }
                }

                case SERVER -> Optional.empty();
            };
        }

        @Override
        public Optional<TlsKeyExchange> newRemoteKeyExchange(TlsContext context, ByteBuffer source) {
            var connectionState = context.remoteConnectionState().orElseThrow(() -> new TlsAlert(
                            "Cannot generate static key exchange: no remote connection state was created",
                            TlsAlertLevel.FATAL,
                            TlsAlertType.HANDSHAKE_FAILURE
                    ));
            return switch (connectionState.type()) {
                case CLIENT -> {
                    if(source == null) {
                        throw new TlsAlert(
                                "Cannot generate static key exchange: received null key exchange source",
                                TlsAlertLevel.FATAL,
                                TlsAlertType.INTERNAL_ERROR
                        );
                    }

                    var preMasterSecret = TlsConnectionSecret.of(readBytesBigEndian16(source));
                    var remoteKeyExchange = new RSAKeyExchange.Client(preMasterSecret);
                    yield Optional.of(remoteKeyExchange);
                }

                case SERVER -> Optional.empty();
            };
        }

        @Override
        public TlsKeyExchangeType type() {
            return TlsKeyExchangeType.STATIC;
        }
    };

    public static TlsKeyExchangeFactory staticFactory() {
        return STATIC_FACTORY;
    }

    @Override
    public TlsKeyExchangeType type() {
        return TlsKeyExchangeType.STATIC;
    }

    private static final class Client extends RSAKeyExchange {
        private final TlsConnectionSecret preMasterSecret;

        private Client(TlsConnectionSecret preMasterSecret) {
            this.preMasterSecret = preMasterSecret;
        }

        @Override
        public void serialize(ByteBuffer buffer) {
            writeBytesBigEndian16(buffer, preMasterSecret.data());
        }

        @Override
        public int length() {
            return INT16_LENGTH + preMasterSecret.length();
        }

        @Override
        public TlsConnectionSecret generatePreSharedSecret(TlsContext context) {
            return preMasterSecret;
        }
    }
}
