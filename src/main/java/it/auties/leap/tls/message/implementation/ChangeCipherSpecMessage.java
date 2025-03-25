package it.auties.leap.tls.message.implementation;

import it.auties.leap.tls.TlsContext;
import it.auties.leap.tls.TlsSource;
import it.auties.leap.tls.TlsException;
import it.auties.leap.tls.message.TlsHandshakeMessage;
import it.auties.leap.tls.message.TlsMessageContentType;
import it.auties.leap.tls.message.TlsMessageMetadata;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;

import static it.auties.leap.tls.util.BufferUtils.*;

public sealed abstract class ChangeCipherSpecMessage extends TlsHandshakeMessage {
    public static final int ID = 0x01;

    ChangeCipherSpecMessage(TlsVersion version, TlsSource source) {
        super(version, source);
    }

    public static ChangeCipherSpecMessage of(TlsContext context, ByteBuffer buffer, TlsMessageMetadata metadata) {
        return switch(context.selectedMode().orElse(null)) {
            case CLIENT -> ChangeCipherSpecMessage.Server.of(metadata.version(), metadata.source(), buffer);
            case SERVER -> ChangeCipherSpecMessage.Client.of(metadata.version(), metadata.source(), buffer);
            case null -> throw new TlsException("No engine mode has been selected yet");
        };
    }

    public static final class Server extends ChangeCipherSpecMessage {
        private static final int LENGTH = INT8_LENGTH;

        public Server(TlsVersion tlsVersion, TlsSource source) {
            super(tlsVersion, source);
        }

        public static Server of(TlsVersion tlsVersion, TlsSource source, ByteBuffer buffer) {
            var messageId = readBigEndianInt8(buffer);
            if(messageId != ID) {
                throw new TlsException("Cannot decode TLS message, invalid change cipher spec message id: " + messageId);
            }

            return new Server(tlsVersion, source);
        }

        @Override
        public byte id() {
            return ID;
        }

        @Override
        public TlsMessageContentType contentType() {
            return TlsMessageContentType.CHANGE_CIPHER_SPEC;
        }

        @Override
        public void serializeHandshakePayload(ByteBuffer buffer) {
            writeBigEndianInt8(buffer, id());
        }

        @Override
        public int handshakePayloadLength() {
            return LENGTH;
        }

        @Override
        public String toString() {
            return "ChangeCipherSpecMessage[" +
                    "tlsVersion=" + version +
                    ']';
        }

        @Override
        public void validateAndUpdate(TlsContext context) {

        }
    }

    public static final class Client extends ChangeCipherSpecMessage {
        private static final int LENGTH = 0;

        public Client(TlsVersion tlsVersion, TlsSource source) {
            super(tlsVersion, source);
        }

        public static Client of(TlsVersion tlsVersion, TlsSource source, ByteBuffer buffer) {
            if(buffer.hasRemaining()) {
                throw new TlsException("Cannot decode TLS message, invalid payload length");
            }

            return new Client(tlsVersion, source);
        }

        @Override
        public byte id() {
            return ID;
        }

        @Override
        public TlsMessageContentType contentType() {
            return TlsMessageContentType.CHANGE_CIPHER_SPEC;
        }

        @Override
        public void serializeHandshakePayload(ByteBuffer buffer) {
            writeBigEndianInt8(buffer, id());
        }

        @Override
        public int handshakePayloadLength() {
            return LENGTH;
        }

        @Override
        public String toString() {
            return "ChangeCipherSpecMessage[" +
                    "tlsVersion=" + version +
                    ']';
        }

        @Override
        public void validateAndUpdate(TlsContext context) {

        }
    }
}
