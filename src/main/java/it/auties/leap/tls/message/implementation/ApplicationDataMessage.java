package it.auties.leap.tls.message.implementation;

import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsContextualProperty;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.message.TlsMessage;
import it.auties.leap.tls.message.TlsMessageContentType;
import it.auties.leap.tls.message.TlsMessageDeserializer;
import it.auties.leap.tls.message.TlsMessageMetadata;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;
import java.util.Objects;
import java.util.Optional;

import static it.auties.leap.tls.util.BufferUtils.*;

public record ApplicationDataMessage(
        TlsSource source,
        byte[] message
) implements TlsMessage {
    private static final int ID = 0x17;

    // FIXME: Is this the correct way to deserialize the message?
    //        What if the handshake is complete? Do we accept messages even then?
    //        I'm guessing yes(ie key update), but I need to check the spec
    private static final TlsMessageDeserializer DESERIALIZER = (context, buffer, metadata) -> {
        var payload = readBytes(buffer, buffer.remaining());
        var message = new ApplicationDataMessage(metadata.source(), payload);
        var version = context.getNegotiatedValue(TlsContextualProperty.version());
        if(version.isEmpty() || (version.get() != TlsVersion.TLS13 && version.get() != TlsVersion.DTLS13)) {
            return Optional.of(message);
        }

        var limit = payload.length;
        while (limit > 0) {
            var contentTypeId = payload[--limit];
            if(contentTypeId == 0) {
                continue;
            }

            var innerMessageContentType = TlsMessageContentType.of(contentTypeId);
            if(innerMessageContentType.isEmpty()) {
                return Optional.of(message);
            }

            var innerMessageMetadata = TlsMessageMetadata.of(innerMessageContentType.get(), metadata.version(), limit, message.source());
            return innerMessageContentType.get()
                    .deserializer()
                    .deserialize(context, ByteBuffer.wrap(payload, 0, limit), innerMessageMetadata)
                    .or(() -> Optional.of(message));
        }

        return Optional.of(message);
    };

    public ApplicationDataMessage {
        Objects.requireNonNull(source, "Invalid source");
        Objects.requireNonNull(message, "Invalid message");
    }

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
        writeBytes(buffer, message);
    }

    @Override
    public int length() {
        return message.length;
    }
    
    @Override
    public void apply(TlsContext context) {
        if (source == TlsSource.REMOTE) {
            context.addBufferedMessage(message);
        }
    }

    @Override
    public void validate(TlsContext context) {

    }
}
