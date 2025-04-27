package it.auties.leap.tls.message.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.message.*;
import it.auties.leap.tls.property.TlsProperty;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;
import java.util.Optional;

import static it.auties.leap.tls.util.BufferUtils.*;

public record ApplicationDataMessage(
        TlsVersion version,
        TlsSource source,
        ByteBuffer message
) implements TlsMessage {
    private static final int ID = 0x17;
    private static final TlsMessageDeserializer DESERIALIZER = (context, buffer, metadata) -> {
        var payload = readBuffer(buffer, buffer.remaining());
        var message = new ApplicationDataMessage(metadata.version(), metadata.source(), payload);
        var version = context.getNegotiatedValue(TlsProperty.version());
        if(version.isEmpty() || (version.get() != TlsVersion.TLS13 && version.get() != TlsVersion.DTLS13)) {
            return Optional.of(message);
        }

        var position = payload.position();
        var limit = payload.limit();
        while (limit > position) {
            var contentTypeId = payload.get(--limit);
            if(contentTypeId == 0) {
                continue;
            }

            var innerMessageContentType = TlsMessageContentType.of(contentTypeId);
            if(innerMessageContentType.isEmpty()) {
                return Optional.of(message);
            }

            payload.limit(limit);
            var innerMessageMetadata = TlsMessageMetadata.of(innerMessageContentType.get(), message.version(), payload.remaining(), message.source());
            return innerMessageContentType.get()
                    .deserializer()
                    .deserialize(context, payload, innerMessageMetadata)
                    .or(() -> Optional.of(message));
        }

        throw new TlsAlert("Missing content type id", TlsAlertLevel.FATAL, TlsAlertType.DECODE_ERROR);
    };

    public static TlsMessageDeserializer deserializer() {
        return DESERIALIZER;
    }

    @Override
    public byte id() {
        return ID;
    }

    @Override
    public TlsMessageContentType contentType() {
        return TlsMessageContentType.APPLICATION_DATA;
    }

    @Override
    public void serialize(ByteBuffer buffer) {
        assertNotEquals(buffer, message);
        writeBuffer(buffer, message);
    }

    @Override
    public void apply(TlsContext context) {
        if (source == TlsSource.REMOTE) {
            context.addBufferedMessage(message);
        }
    }

    @Override
    public int length() {
        return message.remaining();
    }
}
