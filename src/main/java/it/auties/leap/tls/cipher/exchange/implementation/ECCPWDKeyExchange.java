package it.auties.leap.tls.cipher.exchange.implementation;

import it.auties.leap.tls.cipher.exchange.TlsKeyExchange;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchangeFactory;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchangeType;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.ec.TlsECParameters;
import it.auties.leap.tls.ec.TlsECParametersDeserializer;
import it.auties.leap.tls.secret.TlsPreMasterSecretGenerator;

import java.nio.ByteBuffer;

import static it.auties.leap.tls.util.BufferUtils.*;

public sealed abstract class ECCPWDKeyExchange implements TlsKeyExchange {
    private static final TlsKeyExchangeFactory EPHEMERAL_FACTORY = new TlsKeyExchangeFactory() {
        @Override
        public TlsKeyExchange newLocalKeyExchange(TlsContext context) {
            throw new UnsupportedOperationException();
        }

        @Override
        public TlsKeyExchange decodeRemoteKeyExchange(TlsContext context, ByteBuffer buffer) {
            throw new UnsupportedOperationException();
        }

        @Override
        public TlsKeyExchangeType type() {
            return TlsKeyExchangeType.EPHEMERAL;
        }
    };

    public static TlsKeyExchangeFactory ephemeralFactory() {
        return EPHEMERAL_FACTORY;
    }

    @Override
    public TlsKeyExchangeType type() {
        return TlsKeyExchangeType.EPHEMERAL;
    }

    @Override
    public TlsPreMasterSecretGenerator preMasterSecretGenerator() {
        return TlsPreMasterSecretGenerator.eccpwd();
    }

    private static final class Client extends ECCPWDKeyExchange {
        private final byte[] publicKey;
        private final byte[] password;

        private Client(byte[] publicKey, byte[] password) {
            this.password = password;
            this.publicKey = publicKey;
        }

        private Client(ByteBuffer buffer) {
            this.publicKey = readBytesBigEndian8(buffer);
            this.password = readBytesBigEndian8(buffer);
        }

        @Override
        public void serialize(ByteBuffer buffer) {
            writeBytesBigEndian8(buffer, publicKey);
            writeBytesBigEndian8(buffer, password);
        }

        @Override
        public int length() {
            return INT8_LENGTH + publicKey.length +
                    INT8_LENGTH + password.length;
        }
    }

    private static final class Server extends ECCPWDKeyExchange {
        private final byte[] salt;
        private final TlsECParameters params;
        private final byte[] publicKey;
        private final byte[] password;

        private Server(byte[] salt, TlsECParameters params, byte[] publicKey, byte[] password) {
            this.salt = salt;
            this.params = params;
            this.publicKey = publicKey;
            this.password = password;
        }

        private Server(ByteBuffer buffer, TlsECParametersDeserializer decoder) {
            this.salt = readBytesBigEndian8(buffer);
            this.params = decoder.deserialize(buffer);
            this.publicKey = readBytesBigEndian8(buffer);
            this.password = readBytesBigEndian8(buffer);
        }

        @Override
        public void serialize(ByteBuffer buffer) {
            writeBytesBigEndian16(buffer, salt);
            params.serialize(buffer);
            writeBytesBigEndian8(buffer, publicKey);
            writeBytesBigEndian8(buffer, password);
        }

        @Override
        public int length() {
            return INT8_LENGTH + salt.length
                    + params.length()
                    + INT8_LENGTH + publicKey.length
                    + INT8_LENGTH + password.length;
        }
    }
}
