package it.auties.leap.tls.message;

import it.auties.leap.tls.TlsCipher;
import it.auties.leap.tls.TlsVersion;
import it.auties.leap.tls.engine.TlsEngineMode;
import it.auties.leap.tls.message.client.ClientChangeCipherSpecMessage;
import it.auties.leap.tls.message.shared.AlertMessage;
import it.auties.leap.tls.message.shared.ApplicationDataMessage;
import it.auties.leap.tls.message.server.ServerChangeCipherSpecMessage;

import java.nio.ByteBuffer;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

import static it.auties.leap.tls.TlsBuffer.*;

public sealed abstract class TlsMessage
        permits AlertMessage, ApplicationDataMessage, TlsHandshakeMessage {
    public static TlsMessage ofServer(TlsCipher cipher, ByteBuffer buffer, Metadata metadata) {
        var version = metadata.version();
        var source = metadata.source();
        try(var _ = scopedRead(buffer, metadata.messageLength())) {
            return switch (metadata.contentType()) {
                case HANDSHAKE -> TlsHandshakeMessage.ofServer(cipher, buffer, metadata);
                case CHANGE_CIPHER_SPEC -> ServerChangeCipherSpecMessage.of(version, source, buffer);
                case ALERT -> AlertMessage.of(version, source, buffer);
                case APPLICATION_DATA -> ApplicationDataMessage.of(version, source, buffer);
            };
        }
    }

    public static TlsMessage ofClient(TlsCipher cipher, ByteBuffer buffer, Metadata metadata) {
        var version = metadata.version();
        var source = metadata.source();
        try(var _ = scopedRead(buffer, metadata.messageLength())) {
            return switch (metadata.contentType()) {
                case HANDSHAKE -> TlsHandshakeMessage.ofClient(cipher, buffer, metadata);
                case CHANGE_CIPHER_SPEC -> ClientChangeCipherSpecMessage.of(version, source, metadata.messageLength());
                case ALERT -> AlertMessage.of(version, source, buffer);
                case APPLICATION_DATA -> ApplicationDataMessage.of(version, source, buffer);
            };
        }
    }

    protected final TlsVersion version;
    protected final Source source;
    protected TlsMessage(TlsVersion version, Source source) {
        this.version = version;
        this.source = source;
    }

    public TlsVersion version() {
        return version;
    }
    public Source source() {
        return source;
    }

    public abstract byte id();
    public abstract boolean isSupported(TlsVersion version, TlsEngineMode mode, Source source, List<Type> precedingMessages);
    public abstract Type type();
    public abstract ContentType contentType();
    public abstract void serializeMessagePayload(ByteBuffer buffer);
    public abstract int messagePayloadLength();

    public void serializeMessageWithRecord(ByteBuffer payload) {
        var messagePayloadLength = messagePayloadLength();
        var recordLength = messageRecordHeaderLength() + messagePayloadLength;
        try(var _ = scopedWrite(payload, recordLength, true)) {
            writeLittleEndianInt8(payload, contentType().id());
            writeLittleEndianInt8(payload, version().id().major());
            writeLittleEndianInt8(payload, version().id().minor());
            writeLittleEndianInt16(payload, messagePayloadLength);
            serializeMessagePayload(payload);
        }
    }

    public void serializeMessage(ByteBuffer payload) {
        try(var _ = scopedWrite(payload, messagePayloadLength(), true)) {
            serializeMessagePayload(payload);
        }
    }

    public static int messageRecordHeaderLength() {
        return INT8_LENGTH + INT8_LENGTH + INT8_LENGTH + INT16_LENGTH;
    }

    public enum ContentType {
        CHANGE_CIPHER_SPEC((byte) 20, "change_cipher_spec"),
        ALERT((byte) 21, "alert"),
        HANDSHAKE((byte) 22, "handshake"),
        APPLICATION_DATA((byte) 23, "application_data");

        private static final Map<Byte, ContentType> VALUES = Arrays.stream(values())
                .collect(Collectors.toUnmodifiableMap(ContentType::id, Function.identity()));

        public static Optional<ContentType> of(byte value) {
            return Optional.ofNullable(VALUES.get(value));
        }

        private final byte id;
        private final String contentName;
        ContentType(byte id, String contentName) {
            this.id = id;
            this.contentName = contentName;
        }

        public byte id() {
            return id;
        }

        public String contentName() {
            return contentName;
        }
    }

    public enum Type {
        ALERT,
        APPLICATION_DATA,

        SERVER_HELLO_REQUEST,
        SERVER_HELLO,
        SERVER_CERTIFICATE,
        SERVER_CERTIFICATE_REQUEST,
        SERVER_KEY_EXCHANGE,
        SERVER_CHANGE_CIPHER_SPEC,
        SERVER_HELLO_DONE,
        SERVER_FINISHED,

        CLIENT_HELLO,
        CLIENT_CERTIFICATE,
        CLIENT_KEY_EXCHANGE,
        CLIENT_CERTIFICATE_VERIFY,
        CLIENT_CHANGE_CIPHER_SPEC,
        CLIENT_FINISHED
    }

    public enum Source {
        REMOTE,
        LOCAL
    }

    public static final class Metadata {
        private static final int LENGTH = INT8_LENGTH + INT16_LENGTH + INT16_LENGTH;

        private final ContentType contentType;
        private final TlsVersion version;
        private int messageLength;

        public Metadata(ContentType contentType, TlsVersion version, int messageLength) {
            this.contentType = contentType;
            this.version = version;
            this.messageLength = messageLength;
        }

        public static Metadata of(ByteBuffer buffer) {
            var contentTypeId = readLittleEndianInt8(buffer);
            var contentType = ContentType.of(contentTypeId)
                    .orElseThrow(() -> new IllegalArgumentException("Cannot decode TLS message, unknown content type: " + contentTypeId));
            var protocolVersionMajor = readLittleEndianInt8(buffer);
            var protocolVersionMinor = readLittleEndianInt8(buffer);
            var protocolVersion = TlsVersion.of(protocolVersionMajor, protocolVersionMinor)
                    .orElseThrow(() -> new IllegalArgumentException("Cannot decode TLS message, unknown protocol version: major %s, minor %s".formatted(protocolVersionMajor, protocolVersionMinor)));
            var messageLength = readLittleEndianInt16(buffer);
            return new Metadata(contentType, protocolVersion, messageLength);
        }

        public Source source() {
            return Source.REMOTE;
        }

        public static int length() {
            return LENGTH;
        }

        public Metadata setMessageLength(int messageLength) {
            this.messageLength = messageLength;
            return this;
        }

        public ContentType contentType() {
            return contentType;
        }

        public TlsVersion version() {
            return version;
        }

        public int messageLength() {
            return messageLength;
        }

        @Override
        public boolean equals(Object obj) {
            if (obj == this) return true;
            if (obj == null || obj.getClass() != this.getClass()) return false;
            var that = (Metadata) obj;
            return Objects.equals(this.contentType, that.contentType) &&
                    Objects.equals(this.version, that.version) &&
                    this.messageLength == that.messageLength;
        }

        @Override
        public int hashCode() {
            return Objects.hash(contentType, version, messageLength);
        }

        @Override
        public String toString() {
            return "DeserializedMetadata[" +
                    "contentType=" + contentType + ", " +
                    "version=" + version + ", " +
                    "messageLength=" + messageLength + ']';
        }
    }
}
