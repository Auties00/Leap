package it.auties.leap.tls.ciphersuite.exchange.implementation;

import it.auties.leap.tls.ciphersuite.exchange.TlsKeyExchange;
import it.auties.leap.tls.ciphersuite.exchange.TlsKeyExchangeFactory;
import it.auties.leap.tls.ciphersuite.exchange.TlsKeyExchangeType;
import it.auties.leap.tls.connection.TlsConnectionSecret;
import it.auties.leap.tls.context.TlsContext;

import java.nio.ByteBuffer;
import java.util.Optional;

import static it.auties.leap.tls.util.BufferUtils.*;

public sealed abstract class SRPKeyExchange implements TlsKeyExchange {
    private static final TlsKeyExchangeFactory EPHEMERAL_FACTORY = new TlsKeyExchangeFactory() {
        @Override
        public TlsKeyExchange newLocalKeyExchange(TlsContext context) {
            throw new UnsupportedOperationException();
        }

        @Override
        public TlsKeyExchange newRemoteKeyExchange(TlsContext context, ByteBuffer source) {
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
    public Optional<TlsConnectionSecret> generatePreSharedSecret(TlsContext context) {
        throw new UnsupportedOperationException();
    }

    private static final class Client extends SRPKeyExchange {
        private final byte[] srpA;

        private Client(byte[] srpA) {
            this.srpA = srpA;
        }

        private Client(ByteBuffer buffer) {
            this.srpA = readBytesBigEndian16(buffer);
        }

        @Override
        public void serialize(ByteBuffer buffer) {
            writeBytesBigEndian16(buffer, srpA);
        }

        @Override
        public int length() {
            return INT16_LENGTH + srpA.length;
        }
    }

    private static final class Server extends SRPKeyExchange {
        private final byte[] srpN;
        private final byte[] srpG;
        private final byte[] srpS;
        private final byte[] srpB;

        private Server(byte[] srpN, byte[] srpG, byte[] srpS, byte[] srpB) {
            this.srpN = srpN;
            this.srpG = srpG;
            this.srpS = srpS;
            this.srpB = srpB;
        }

        private Server(ByteBuffer buffer) {
            this.srpN = readBytesBigEndian16(buffer);
            this.srpG = readBytesBigEndian16(buffer);
            this.srpS = readBytesBigEndian8(buffer);
            this.srpB = readBytesBigEndian16(buffer);
        }

        @Override
        public void serialize(ByteBuffer buffer) {
            writeBytesBigEndian16(buffer, srpN);
            writeBytesBigEndian16(buffer, srpG);
            writeBytesBigEndian8(buffer, srpS);
            writeBytesBigEndian16(buffer, srpB);
        }

        @Override
        public int length() {
            return INT16_LENGTH + srpN.length
                    + INT16_LENGTH + srpG.length
                    + INT8_LENGTH + srpS.length
                    + INT16_LENGTH + srpB.length;
        }
    }
}
