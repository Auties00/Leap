package it.auties.leap.tls.message;

import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.message.implementation.TlsAnyMessageDeserializer;
import it.auties.leap.tls.message.implementation.TlsStandardMessageDeserializer;

import java.nio.ByteBuffer;
import java.util.Optional;

@FunctionalInterface
public interface TlsMessageDeserializer {
    static TlsMessageDeserializer standard() {
        return TlsStandardMessageDeserializer.instance();
    }

    static TlsMessageDeserializer any(TlsMessageDeserializer... deserializers) {
        return new TlsAnyMessageDeserializer(deserializers);
    }

    Optional<TlsMessage> deserialize(TlsContext context, ByteBuffer buffer, TlsMessageMetadata metadata);
}
