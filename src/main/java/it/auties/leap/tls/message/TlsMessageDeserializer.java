package it.auties.leap.tls.message;

import it.auties.leap.tls.context.TlsContext;

import java.nio.ByteBuffer;

@FunctionalInterface
public interface TlsMessageDeserializer {
    TlsMessage deserialize(TlsContext context, ByteBuffer buffer, TlsMessageMetadata metadata);
}
