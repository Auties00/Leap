package it.auties.leap.tls.cipher.exchange.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchange;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchangeFactory;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchangeType;
import it.auties.leap.tls.connection.TlsConnectionType;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.secret.preMaster.TlsPreMasterSecretGenerator;
import it.auties.leap.tls.secret.TlsSecret;

import java.nio.ByteBuffer;
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

            var preMasterSecret = TlsPreMasterSecretGenerator.rsa()
                    .generatePreMasterSecret(context);
            return new RSAKeyExchange.Client(preMasterSecret);
        }

        @Override
        public TlsKeyExchange newRemoteKeyExchange(TlsContext context, ByteBuffer ephemeralKeyExchangeSource) {
            var mode = context.localConnectionState().type();
            if (mode == TlsConnectionType.SERVER) {
                throw new TlsAlert("Unsupported RSA key exchange", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
            }

            return new RSAKeyExchange.Client(ephemeralKeyExchangeSource);
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

    @Override
    public TlsPreMasterSecretGenerator preMasterSecretGenerator() {
        return TlsPreMasterSecretGenerator.rsa();
    }

    private static final class Client extends RSAKeyExchange {
        private final TlsSecret preMasterSecret;

        private Client(TlsSecret preMasterSecret) {
            this.preMasterSecret = preMasterSecret;
        }

        private Client(ByteBuffer buffer) {
            this.preMasterSecret = TlsSecret.of(readBytesBigEndian16(buffer));
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
        public Optional<TlsSecret> preMasterSecret() {
            return Optional.of(preMasterSecret);
        }
    }
}
