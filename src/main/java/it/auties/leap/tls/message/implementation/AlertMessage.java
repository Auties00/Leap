package it.auties.leap.tls.message.implementation;

import it.auties.leap.socket.SocketException;
import it.auties.leap.tls.TlsContext;
import it.auties.leap.tls.TlsSource;
import it.auties.leap.tls.TlsException;
import it.auties.leap.tls.message.*;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;

import static it.auties.leap.tls.util.BufferUtils.*;

public final class AlertMessage extends TlsMessage {
    private static final int LENGTH = INT8_LENGTH + INT8_LENGTH;

    private final TlsAlertLevel alertLevel;
    private final TlsAlertType alertType;

    public AlertMessage(TlsVersion tlsVersion, TlsSource source, TlsAlertLevel alertLevel, TlsAlertType alertType) {
        super(tlsVersion, source);
        this.alertLevel = alertLevel;
        this.alertType = alertType;
    }

    public static AlertMessage of(TlsContext ignoredEngine, ByteBuffer buffer, TlsMessageMetadata metadata) {
        var levelId = readBigEndianInt8(buffer);
        var level = TlsAlertLevel.of(levelId)
                .orElseThrow(() -> new IllegalArgumentException("Cannot decode TLS message, unknown alert level: " + levelId));
        var typeId = readBigEndianInt8(buffer);
        var type = TlsAlertType.of(typeId)
                .orElseThrow(() -> new IllegalArgumentException("Cannot decode TLS message, unknown alert type: " + typeId));
        return new AlertMessage(metadata.version(), metadata.source(), level, type);
    }

    @Override
    public byte id() {
        return 0x00;
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

    @Override
    public void validateAndUpdate(TlsContext context) {
        if(alertType == TlsAlertType.CLOSE_NOTIFY) {
            throw SocketException.closed();
        }

        throw new TlsException("Received alert: " + context);
    }

}
