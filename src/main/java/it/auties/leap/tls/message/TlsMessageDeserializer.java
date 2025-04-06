package it.auties.leap.tls.message;

import it.auties.leap.tls.context.TlsContext;

import java.nio.ByteBuffer;

public interface TlsMessageDeserializer {
    int id();
    TlsMessage deserialize(TlsContext context, ByteBuffer buffer, TlsMessageMetadata metadata);
}
