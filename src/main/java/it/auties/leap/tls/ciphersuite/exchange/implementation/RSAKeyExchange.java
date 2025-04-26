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
import it.auties.leap.tls.property.TlsProperty;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Optional;

import static it.auties.leap.tls.util.BufferUtils.*;

public sealed abstract class RSAKeyExchange implements TlsKeyExchange {
    private static final TlsKeyExchangeFactory STATIC_FACTORY = new TlsKeyExchangeFactory() {
        @Override
        public TlsKeyExchange newLocalKeyExchange(TlsContext context) {
            var mode = context.localConnectionState().type();
            if (mode == TlsConnectionType.SERVER) {
                throw new TlsAlert("Unsupported RSA key exchange", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
            }

            try {
                var preMasterSecret = new byte[48];
                SecureRandom.getInstanceStrong()
                        .nextBytes(preMasterSecret);
                var version = context.getNegotiatedValue(TlsProperty.version())
                        .orElseThrow(() -> new TlsAlert("Missing negotiable property: version", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR));
                preMasterSecret[0] = version.id().minor();
                preMasterSecret[1] = version.id().major();
                var cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                var remoteCertificate = context.remoteConnectionState()
                        .orElseThrow(() -> new TlsAlert("No remote connection state was created", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR))
                        .staticCertificate()
                        .orElseThrow(() -> new TlsAlert("Expected at least one static certificate", TlsAlertLevel.FATAL, TlsAlertType.CERTIFICATE_UNOBTAINABLE));
                cipher.init(Cipher.WRAP_MODE, remoteCertificate.value());
                var encryptedPreMasterSecret = TlsConnectionSecret.of(cipher.wrap(new SecretKeySpec(preMasterSecret, "raw")));
                return new Client(encryptedPreMasterSecret);
            }catch (GeneralSecurityException exception) {
                throw new TlsAlert("Cannot generate pre master secret: " + exception.getMessage(), TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
            }
        }

        @Override
        public TlsKeyExchange newRemoteKeyExchange(TlsContext context, ByteBuffer source) {
            var mode = context.localConnectionState().type();
            if (mode == TlsConnectionType.SERVER) {
                throw new TlsAlert("Unsupported RSA key exchange", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
            }

            if(source == null) {
                throw new TlsAlert("Expected a valid payload for remote RSA key exchange", TlsAlertLevel.FATAL, TlsAlertType.DECODE_ERROR);
            }

            var preMasterSecret = TlsConnectionSecret.of(readBytesBigEndian16(source));
            return new RSAKeyExchange.Client(preMasterSecret);
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
        public Optional<TlsConnectionSecret> generatePreSharedSecret(TlsContext context) {
            return Optional.of(preMasterSecret);
        }
    }
}
