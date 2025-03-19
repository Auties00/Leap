package it.auties.leap.tls.message.implementation;

import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.message.TlsMessageContentType;
import it.auties.leap.tls.message.TlsMessageMetadata;
import it.auties.leap.tls.version.TlsVersion;
import it.auties.leap.tls.message.TlsMessage;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;

import static it.auties.leap.tls.util.BufferUtils.*;

public final class AlertMessage extends TlsMessage {
    private static final int LENGTH = INT8_LENGTH + INT8_LENGTH;

    private final AlertLevel alertLevel;
    private final AlertType alertType;

    public AlertMessage(TlsVersion tlsVersion, TlsSource source, AlertLevel alertLevel, AlertType alertType) {
        super(tlsVersion, source);
        this.alertLevel = alertLevel;
        this.alertType = alertType;
    }

    public static AlertMessage of(TlsContext ignoredEngine, ByteBuffer buffer, TlsMessageMetadata metadata) {
        var levelId = readBigEndianInt8(buffer);
        var level = AlertLevel.of(levelId)
                .orElseThrow(() -> new IllegalArgumentException("Cannot decode TLS message, unknown alert level: " + levelId));
        var typeId = readBigEndianInt8(buffer);
        var type = AlertType.of(typeId)
                .orElseThrow(() -> new IllegalArgumentException("Cannot decode TLS message, unknown alert type: " + typeId));
        return new AlertMessage(metadata.version(), metadata.source(), level, type);
    }

    @Override
    public byte id() {
        return 0x00;
    }

    public AlertLevel alertLevel() {
        return alertLevel;
    }

    public AlertType alertType() {
        return alertType;
    }

    @Override
    public TlsMessageContentType contentType() {
        return TlsMessageContentType.ALERT;
    }

    @Override
    public void serializeMessagePayload(ByteBuffer buffer) {
        writeBigEndianInt8(buffer, alertLevel.id());
        writeBigEndianInt8(buffer, alertType.id());
    }

    @Override
    public int messagePayloadLength() {
        return LENGTH;
    }

    @Override
    public String toString() {
        return "AlertMessage[" +
                "tlsVersion=" + version +
                ", level=" + alertLevel +
                ", type=" + alertType +
                ']';
    }

    public enum AlertType {
        CLOSE_NOTIFY((byte) 0, "close_notify", false),
        UNEXPECTED_MESSAGE((byte) 10, "unexpected_message", false),
        BAD_RECORD_MAC((byte) 20, "bad_record_mac", false),
        DECRYPTION_FAILED((byte) 21, "decryption_failed", false),
        RECORD_OVERFLOW((byte) 22, "record_overflow", false),
        DECOMPRESSION_FAILURE((byte) 30, "decompression_failure", false),
        HANDSHAKE_FAILURE((byte) 40, "handshake_failure", true),
        NO_CERTIFICATE((byte) 41, "no_certificate", true),
        BAD_CERTIFICATE((byte) 42, "bad_certificate", true),
        UNSUPPORTED_CERTIFICATE((byte) 43, "unsupported_certificate", true),
        CERTIFICATE_REVOKED((byte) 44, "certificate_revoked", true),
        CERTIFICATE_EXPIRED((byte) 45, "certificate_expired", true),
        CERTIFICATE_UNKNOWN((byte) 46, "certificate_unknown", true),
        ILLEGAL_PARAMETER((byte) 47, "illegal_parameter", true),
        UNKNOWN_CA((byte) 48, "unknown_ca", true),
        ACCESS_DENIED((byte) 49, "access_denied", true),
        DECODE_ERROR((byte) 50, "decode_error", true),
        DECRYPT_ERROR((byte) 51, "decrypt_error", true),
        EXPORT_RESTRICTION((byte) 60, "export_restriction", true),
        PROTOCOL_VERSION((byte) 70, "protocol_version", true),
        INSUFFICIENT_SECURITY((byte) 71, "insufficient_security", true),
        INTERNAL_ERROR((byte) 80, "internal_error", false),
        INAPPROPRIATE_FALLBACK((byte) 86, "inappropriate_fallback", false),
        USER_CANCELED((byte) 90, "user_canceled", false),
        NO_RENEGOTIATION((byte) 100, "no_renegotiation", true),
        MISSING_EXTENSION((byte) 109, "missing_extension", true),
        UNSUPPORTED_EXTENSION((byte) 110, "unsupported_extension", true),
        CERT_UNOBTAINABLE((byte) 111, "certificate_unobtainable", true),
        UNRECOGNIZED_NAME((byte) 112, "unrecognized_name", true),
        BAD_CERT_STATUS_RESPONSE((byte) 113, "bad_certificate_status_response", true),
        BAD_CERT_HASH_VALUE((byte) 114, "bad_certificate_hash_value", true),
        UNKNOWN_PSK_IDENTITY((byte) 115, "unknown_psk_identity", true),
        CERTIFICATE_REQUIRED((byte) 116, "certificate_required", true),
        NO_APPLICATION_PROTOCOL((byte) 120, "no_application_protocol", true);
        
        private static final Map<Byte, AlertType> VALUES = Arrays.stream(values())
                .collect(Collectors.toUnmodifiableMap(AlertType::id, Function.identity()));

        private final byte id;
        private final String description;
        private final boolean handshakeOnly;
        AlertType(byte id, String description, boolean handshakeOnly) {
            this.id = id;
            this.description = description;
            this.handshakeOnly = handshakeOnly;
        }

        public static Optional<AlertType> of(byte id) {
            return Optional.ofNullable(VALUES.get(id));
        }

        public byte id() {
            return id;
        }

        public String description() {
            return description;
        }

        public boolean handshakeOnly() {
            return handshakeOnly;
        }
    }

    public enum AlertLevel {
        WARNING((byte) 1, "warning"),
        FATAL((byte) 2, "fatal");

        private static final Map<Byte, AlertLevel> VALUES = Arrays.stream(values())
                .collect(Collectors.toUnmodifiableMap(AlertLevel::id, Function.identity()));
        
        private final byte id;
        private final String description;
        AlertLevel(byte id, String description) {
            this.id = id;
            this.description = description;
        }

        public static Optional<AlertLevel> of(byte level) {
            return Optional.ofNullable(VALUES.get(level));
        }

        public byte id() {
            return id;
        }

        public String description() {
            return description;
        }
    }
}
