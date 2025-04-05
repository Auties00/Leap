package it.auties.leap.tls.message;

import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.message.implementation.StandardMessageDeserializer;

import java.nio.ByteBuffer;
import java.util.Optional;

@FunctionalInterface
public interface TlsMessageDeserializer {
    static TlsMessageDeserializer of(TlsMessageDeserializer... deserializers) {
        return (context, buffer, metadata) -> {
            for (var deserializer : deserializers) {
                var result = deserializer.deserialize(context, buffer, metadata);
                if (result.isPresent()) {
                    return result;
                }
            }
            return Optional.empty();
        };
    }

    static TlsMessageDeserializer builtin() {
        return StandardMessageDeserializer.instance();
    }

    Optional<TlsMessage> deserialize(TlsContext context, ByteBuffer buffer, TlsMessageMetadata metadata);
}
