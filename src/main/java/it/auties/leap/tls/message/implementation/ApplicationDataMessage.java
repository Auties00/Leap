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
            return message;
        }

        while (payload.hasRemaining()) {
            var contentTypeIdPosition = payload.limit() - 1;
            var contentTypeId = payload.get(contentTypeIdPosition);
            payload.limit(contentTypeIdPosition);
            if(contentTypeId == 0) {
                continue;
            }

            var innerMessageContentType = TlsMessageContentType.of(contentTypeId)
                    .orElseThrow(() -> new TlsAlert("Unknown content type id", TlsAlertLevel.FATAL, TlsAlertType.DECODE_ERROR));
            var innerMessageMetadata = TlsMessageMetadata.of(innerMessageContentType, message.version(), payload.remaining(), message.source());
            return innerMessageContentType.deserializer()
                    .deserialize(context, payload, innerMessageMetadata);
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
