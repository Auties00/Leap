package it.auties.leap.tls.cipher.exchange.implementation;

import it.auties.leap.tls.cipher.exchange.TlsKeyExchange;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchangeFactory;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchangeType;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsMode;
import it.auties.leap.tls.exception.TlsException;
import it.auties.leap.tls.secret.TlsPreMasterSecretGenerator;

import java.nio.ByteBuffer;
import java.util.Optional;

import static it.auties.leap.tls.util.BufferUtils.*;

public sealed abstract class RSAKeyExchange implements TlsKeyExchange {
    private static final TlsKeyExchangeFactory STATIC_FACTORY = new TlsKeyExchangeFactory() {
        @Override
        public TlsKeyExchange newLocalKeyExchange(TlsContext context) {
            var mode = context.selectedMode()
                    .orElseThrow(() -> new TlsException("No mode was selected"));
            if (mode == TlsMode.SERVER) {
                throw new TlsException("Unsupported RSA key exchange");
            }

            var preMasterSecret = TlsPreMasterSecretGenerator.rsa()
                    .generatePreMasterSecret(context);
            return new RSAKeyExchange.Client(preMasterSecret);
        }

        @Override
        public TlsKeyExchange decodeRemoteKeyExchange(TlsContext context, ByteBuffer buffer) {
            var mode = context.selectedMode()
                    .orElseThrow(() -> new TlsException("No mode was selected"));
            if (mode == TlsMode.SERVER) {
                throw new TlsException("Unsupported RSA key exchange");
            }

            return new RSAKeyExchange.Client(buffer);
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
        private final byte[] preMasterSecret;

        private Client(byte[] preMasterSecret) {
            this.preMasterSecret = preMasterSecret;
        }

        private Client(ByteBuffer buffer) {
            this.preMasterSecret = readBytesBigEndian16(buffer);
        }

        @Override
        public void serialize(ByteBuffer buffer) {
            writeBytesBigEndian16(buffer, preMasterSecret);
        }

        @Override
        public int length() {
            return INT16_LENGTH + preMasterSecret.length;
        }

        @Override
        public Optional<byte[]> preMasterSecret() {
            return Optional.of(preMasterSecret);
        }
    }
}
