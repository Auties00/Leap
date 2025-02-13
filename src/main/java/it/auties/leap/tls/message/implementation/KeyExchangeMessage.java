package it.auties.leap.tls.message.implementation;

import it.auties.leap.tls.TlsContext;
import it.auties.leap.tls.TlsSource;
import it.auties.leap.tls.cipher.exchange.TlsClientKeyExchange;
import it.auties.leap.tls.cipher.exchange.TlsServerKeyExchange;
import it.auties.leap.tls.message.TlsHandshakeMessage;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;
import java.util.Optional;

import static it.auties.leap.tls.util.BufferUtils.*;

public sealed abstract class KeyExchangeMessage extends TlsHandshakeMessage {
    KeyExchangeMessage(TlsVersion version, TlsSource source) {
        super(version, source);
    }

    public static final class Server extends KeyExchangeMessage {
        public static final byte ID = 0x0C;

        private final TlsServerKeyExchange parameters;
        private final int signatureAlgorithm;
        private final byte[] signature;
        public Server(TlsVersion tlsVersion, TlsSource source, TlsServerKeyExchange parameters, int signatureAlgorithm, byte[] signature) {
            super(tlsVersion, source);
            this.parameters = parameters;
            this.signatureAlgorithm = signatureAlgorithm;
            this.signature = signature;
        }

        public static Server of(TlsContext context, ByteBuffer buffer, Metadata metadata) {
            var remoteParameters = (TlsServerKeyExchange) context.negotiatedCipher()
                    .orElseThrow()
                    .keyExchangeFactory()
                    .decodeRemoteKeyExchange(context, buffer);
            var signatureAlgorithmId = readBigEndianInt16(buffer);
            var signature = readBytesBigEndian16(buffer);
            return new Server(metadata.version(), metadata.source(), remoteParameters, signatureAlgorithmId, signature);
        }

        @Override
        public byte id() {
            return ID;
        }

        @Override
        public Type type() {
            return Type.SERVER_KEY_EXCHANGE;
        }

        public TlsServerKeyExchange parameters() {
            return parameters;
        }

        public int signatureAlgorithm() {
            return signatureAlgorithm;
        }

        public byte[] signature() {
            return signature;
        }

        @Override
        public ContentType contentType() {
            return ContentType.HANDSHAKE;
        }

        @Override
        public void serializeHandshakePayload(ByteBuffer buffer) {
            parameters.serialize(buffer);
            writeBigEndianInt16(buffer, signatureAlgorithm);
            writeBytesBigEndian16(buffer, signature);
        }

        @Override
        public int handshakePayloadLength() {
            return parameters.length()
                    + INT16_LENGTH
                    + INT16_LENGTH
                    + signature.length;
        }
    }

    public static final class Client extends KeyExchangeMessage {
        public static final byte ID = 0x10;

        private final TlsClientKeyExchange localParameters;
        private final ByteBuffer remoteParameters;
        public Client(TlsVersion tlsVersion, TlsSource source, TlsClientKeyExchange localParameters) {
            super(tlsVersion, source);
            this.localParameters = localParameters;
            this.remoteParameters = null;
        }

        private Client(TlsVersion tlsVersion, TlsSource source, ByteBuffer remoteParameters) {
            super(tlsVersion, source);
            this.localParameters = null;
            this.remoteParameters = remoteParameters;
        }

        public static Client of(TlsContext ignoredEngine, ByteBuffer buffer, Metadata metadata) {
            var messageLength = readBigEndianInt24(buffer);
            try(var _ = scopedRead(buffer, messageLength)) {
                return new Client(metadata.version(), metadata.source(), readBuffer(buffer, buffer.remaining()));
            }
        }

        @Override
        public byte id() {
            return ID;
        }

        public Optional<TlsClientKeyExchange> localParameters() {
            return Optional.ofNullable(localParameters);
        }

        public Optional<TlsClientKeyExchange> remoteParameters() {
            return Optional.ofNullable(localParameters);
        }

        @Override
        public Type type() {
            return Type.CLIENT_KEY_EXCHANGE;
        }

        @Override
        public ContentType contentType() {
            return ContentType.HANDSHAKE;
        }

        @Override
        public void serializeHandshakePayload(ByteBuffer buffer) {
            if(localParameters != null) {
                localParameters.serialize(buffer);
            }else if(remoteParameters != null) {
                writeBuffer(buffer, remoteParameters);
            }
        }

        @Override
        public int handshakePayloadLength() {
            if(localParameters != null) {
                return localParameters.length();
            }else if(remoteParameters != null) {
                return remoteParameters.remaining();
            }else {
                return 0;
            }
        }
    }
}
