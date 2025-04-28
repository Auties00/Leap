package it.auties.leap.tls.message.implementation;

import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.message.TlsMessage;
import it.auties.leap.tls.message.TlsMessageDeserializer;
import it.auties.leap.tls.message.TlsMessageMetadata;

import java.nio.ByteBuffer;
import java.util.Optional;

import static it.auties.leap.tls.util.BufferUtils.*;

public final class HandshakeMessageDeserializer implements TlsMessageDeserializer {
    private static final HandshakeMessageDeserializer INSTANCE = new HandshakeMessageDeserializer();

    private HandshakeMessageDeserializer() {

    }

    public static TlsMessageDeserializer instance() {
        return INSTANCE;
    }

    @Override
    public Optional<TlsMessage> deserialize(TlsContext context, ByteBuffer buffer, TlsMessageMetadata metadata) {
        var position = buffer.position();
        var id = readBigEndianInt8(buffer);
        var handshakePayloadLength = readBigEndianInt24(buffer);
        try (var _ = scopedRead(buffer, handshakePayloadLength)) {
            var result = context.findHandshakeMessageDeserializer(id)
                    .map(deserializer -> deserializer.deserialize(context, buffer, metadata.withLength(handshakePayloadLength)));
            if(result.isPresent()) {
                var nextPosition = buffer.position();
                var hash = context.connectionHandshakeHash();
                hash.update(buffer.position(position));
                hash.commit();
                buffer.position(nextPosition);
            }
            return result;
        }
    }
}
