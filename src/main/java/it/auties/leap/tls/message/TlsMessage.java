package it.auties.leap.tls.message;

import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;
import java.util.Optional;

import static it.auties.leap.tls.util.BufferUtils.*;
import static it.auties.leap.tls.util.BufferUtils.scopedRead;

public interface TlsMessage {
    static Optional<TlsMessage> of(TlsContext context, ByteBuffer buffer, TlsMessageMetadata metadata) {
        try(var _ = scopedRead(buffer, metadata.length())) {
            return switch (metadata.contentType()) {
                case HANDSHAKE -> {
                    var id = readBigEndianInt8(buffer);
                    var handshakePayloadLength = readBigEndianInt24(buffer);
                    try (var _ = scopedRead(buffer, handshakePayloadLength)) {
                        yield context.findHandshakeMessageDeserializer(id)
                                .map(deserializer -> deserializer.deserialize(context, buffer, metadata.withLength(handshakePayloadLength)));
                    }
                }
                case CHANGE_CIPHER_SPEC -> {
                    var deserializer = TlsMessageDeserializer.changeCipherSpec();
                    yield Optional.of(deserializer.deserialize(context, buffer, metadata));
                }
                case ALERT -> {
                    var deserializer = TlsMessageDeserializer.alert();
                    yield Optional.of(deserializer.deserialize(context, buffer, metadata));
                }
                case APPLICATION_DATA -> {
                    var deserializer = TlsMessageDeserializer.applicationData();
                    yield Optional.of(deserializer.deserialize(context, buffer, metadata));
                }
            };
        }
    }

    byte id();
    TlsVersion version();
    TlsSource source();
    TlsMessageContentType contentType();
    void serialize(ByteBuffer buffer);
    int length();
    void apply(TlsContext context);
}
