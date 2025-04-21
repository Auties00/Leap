package it.auties.leap.tls.message.implementation;

import it.auties.leap.socket.SocketException;
import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.message.*;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;

import static it.auties.leap.tls.util.BufferUtils.*;

public record AlertMessage(
        TlsVersion tlsVersion,
        TlsSource source,
        TlsAlertLevel alertLevel,
        TlsAlertType alertType
) implements TlsMessage {
    private static final int ID = 0x00;
    private static final TlsMessageDeserializer DESERIALIZER = (_, buffer, metadata) -> {
        var levelId = readBigEndianInt8(buffer);
        var level = TlsAlertLevel.of(levelId)
                .orElseThrow(() -> new IllegalArgumentException("Cannot decode TLS message, unknown alert level: " + levelId));
        var typeId = readBigEndianInt8(buffer);
        var type = TlsAlertType.of(typeId)
                .orElseThrow(() -> new IllegalArgumentException("Cannot decode TLS message, unknown alert type: " + typeId));
        return new AlertMessage(metadata.version(), metadata.source(), level, type);
    };

    public static TlsMessageDeserializer deserializer() {
        return DESERIALIZER;
    }

    @Override
    public byte id() {
        return ID;
    }

    @Override
    public TlsVersion version() {
        return tlsVersion;
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

        throw new TlsAlert("Received alert: " + alertType + "(" + alertLevel + ")", alertLevel, alertType);
    }
}
