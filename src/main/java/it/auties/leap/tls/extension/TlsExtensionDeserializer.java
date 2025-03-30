package it.auties.leap.tls.extension;

import it.auties.leap.tls.context.TlsContext;

import java.nio.ByteBuffer;
import java.util.Optional;

public interface TlsExtensionDeserializer<T extends TlsExtension.Configured> {
    Optional<? extends T> deserialize(TlsContext context, int type, ByteBuffer buffer);
}
