package it.auties.leap.tls.message.implementation;

import it.auties.leap.socket.SocketException;
import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.message.TlsMessage;
import it.auties.leap.tls.message.TlsMessageContentType;
import it.auties.leap.tls.message.TlsMessageDeserializer;

import java.nio.ByteBuffer;
import java.util.Objects;
import java.util.Optional;

import static it.auties.leap.tls.util.BufferUtils.*;

public record AlertMessage(
        TlsSource source,
        TlsAlertLevel alertLevel,
        TlsAlertType alertType
) implements TlsMessage {
    private static final int ID = 0x00;
    private static final TlsMessageDeserializer DESERIALIZER = (_, buffer, metadata) -> {
        var levelId = readBigEndianInt8(buffer);
        var level = TlsAlertLevel.of(levelId).orElseThrow(() -> new TlsAlert(
                "Cannot decode AlertMessage: unknown alert level " + levelId,
                TlsAlertLevel.FATAL,
                TlsAlertType.DECODE_ERROR
        ));
        var typeId = readBigEndianInt8(buffer);
        var type = TlsAlertType.of(typeId).orElseThrow(() -> new TlsAlert(
                "Cannot decode AlertMessage: unknown alert type " + typeId,
                TlsAlertLevel.FATAL,
                TlsAlertType.DECODE_ERROR
        ));
        var message = new AlertMessage(metadata.source(), level, type);
        return Optional.of(message);
    };

    public AlertMessage {
        Objects.requireNonNull(source, "Invalid source");
        Objects.requireNonNull(alertLevel, "Invalid alert level");
        Objects.requireNonNull(alertType, "Invalid alert type");
    }

    public static TlsMessageDeserializer deserializer() {
        return DESERIALIZER;
    }

    @Override
    public byte id() {
        return ID;
    }

    @Override
    public TlsSource source() {
        return source;
    }

    @Override
    public TlsMessageContentType contentType() {
        return TlsMessageContentType.ALERT;
    }

    @Override
    public void serialize(ByteBuffer buffer) {
        writeBigEndianInt8(buffer, alertLevel.id());
        writeBigEndianInt8(buffer, alertType.id());
    }

    @Override
    public int length() {
        return INT8_LENGTH + INT8_LENGTH;
    }

    @Override
    public void apply(TlsContext context) {
        if(alertType == TlsAlertType.CLOSE_NOTIFY) {
            throw SocketException.closed();
        }

        throw new TlsAlert(
                "(" + alertLevel.name().toLowerCase() + ") " + alertType.name().toLowerCase(),
                alertLevel,
                alertType
        );
    }

    @Override
    public void validate(TlsContext context) {

    }
}
