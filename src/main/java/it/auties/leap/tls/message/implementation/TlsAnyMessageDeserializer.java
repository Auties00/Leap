package it.auties.leap.tls.message.implementation;

import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.message.TlsMessage;
import it.auties.leap.tls.message.TlsMessageDeserializer;
import it.auties.leap.tls.message.TlsMessageMetadata;

import java.nio.ByteBuffer;
import java.util.Optional;

public final class TlsAnyMessageDeserializer implements TlsMessageDeserializer {
    private final TlsMessageDeserializer[] deserializers;

    public TlsAnyMessageDeserializer(TlsMessageDeserializer... deserializers) {
        this.deserializers = deserializers;
    }

    @Override
    public Optional<TlsMessage> deserialize(TlsContext context, ByteBuffer buffer, TlsMessageMetadata metadata) {
        for (var deserializer : deserializers) {
            var result = deserializer.deserialize(context, buffer, metadata);
            if (result.isPresent()) {
                return result;
            }
        }
        return Optional.empty();
    }
}
