package it.auties.leap.tls.message.implementation;

import it.auties.leap.tls.property.TlsProperty;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchange;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchangeType;
import it.auties.leap.tls.TlsContext;
import it.auties.leap.tls.TlsSource;
import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.message.TlsHandshakeMessage;
import it.auties.leap.tls.message.TlsMessageContentType;
import it.auties.leap.tls.message.TlsMessageMetadata;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;

import static it.auties.leap.tls.util.BufferUtils.*;

public sealed abstract class KeyExchangeMessage extends TlsHandshakeMessage {
    KeyExchangeMessage(TlsVersion version, TlsSource source) {
        super(version, source);
    }

    public static final class Server extends KeyExchangeMessage {
        public static final byte ID = 0x0C;

        private final TlsKeyExchange parameters;
        private final int signatureAlgorithm;
        private final byte[] signature;
        public Server(TlsVersion tlsVersion, TlsSource source, TlsKeyExchange parameters, int signatureAlgorithm, byte[] signature) {
            super(tlsVersion, source);
            this.parameters = parameters;
            this.signatureAlgorithm = signatureAlgorithm;
            this.signature = signature;
        }

        public static Server of(TlsContext context, ByteBuffer buffer, TlsMessageMetadata metadata) {
            var remoteParameters = context.getNegotiatedValue(TlsProperty.cipher())
                    .orElseThrow(() -> TlsAlert.noNegotiatedProperty(TlsProperty.cipher()))
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
        public TlsMessageContentType contentType() {
            return TlsMessageContentType.HANDSHAKE;
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

        @Override
        public void apply(TlsContext context) {
            var negotiatedCipher = context.getNegotiatedValue(TlsProperty.cipher())
                    .orElseThrow(() -> TlsAlert.noNegotiatedProperty(TlsProperty.cipher()));
            if(negotiatedCipher.keyExchangeFactory().type() != TlsKeyExchangeType.EPHEMERAL) {
                throw new TlsAlert("Unexpected server key exchange message for static key exchange");
            }

            switch (source) {
                case LOCAL -> context.localConnectionState()
                        .setKeyExchange(parameters);
                case REMOTE -> {
                    context.remoteConnectionState()
                            .orElseThrow(TlsAlert::noRemoteConnectionState)
                            .setKeyExchange(parameters);
                    var localKeyExchange = negotiatedCipher.keyExchangeFactory()
                            .newLocalKeyExchange(context);
                    context.localConnectionState()
                            .setKeyExchange(localKeyExchange);
                }
            }
        }
    }

    public static final class Client extends KeyExchangeMessage {
        public static final byte ID = 0x10;

        private final TlsKeyExchange parameters;
        public Client(TlsVersion tlsVersion, TlsSource source, TlsKeyExchange parameters) {
            super(tlsVersion, source);
            this.parameters = parameters;
        }

        public static Client of(TlsContext context, ByteBuffer buffer, TlsMessageMetadata metadata) {
            var messageLength = readBigEndianInt24(buffer);
            try(var _ = scopedRead(buffer, messageLength)) {
                var remoteParameters = context.getNegotiatedValue(TlsProperty.cipher())
                        .orElseThrow(() -> TlsAlert.noNegotiatedProperty(TlsProperty.cipher()))
                        .keyExchangeFactory()
                        .decodeRemoteKeyExchange(context, buffer);
                return new Client(metadata.version(), metadata.source(), remoteParameters);
            }
        }

        @Override
        public byte id() {
            return ID;
        }

        @Override
        public TlsMessageContentType contentType() {
            return TlsMessageContentType.HANDSHAKE;
        }

        @Override
        public void serializeHandshakePayload(ByteBuffer buffer) {
            parameters.serialize(buffer);
        }

        @Override
        public int handshakePayloadLength() {
            return parameters.length();
        }

        @Override
        public void apply(TlsContext context) {
            var negotiatedCipher = context.getNegotiatedValue(TlsProperty.cipher())
                    .orElseThrow(() -> TlsAlert.noNegotiatedProperty(TlsProperty.cipher()));
            if(negotiatedCipher.keyExchangeFactory().type() != TlsKeyExchangeType.EPHEMERAL) {
                throw new TlsAlert("Unexpected client key exchange message for static key exchange");
            }

            switch (source) {
                case LOCAL -> context.localConnectionState()
                        .setKeyExchange(parameters);
                case REMOTE -> {
                    context.remoteConnectionState()
                            .orElseThrow(TlsAlert::noRemoteConnectionState)
                            .setKeyExchange(parameters);
                    var localKeyExchange = negotiatedCipher.keyExchangeFactory()
                            .newLocalKeyExchange(context);
                    context.localConnectionState()
                            .setKeyExchange(localKeyExchange);
                }
            }

            context.connectionInitializer()
                    .initialize(context);
        }
    }
}
