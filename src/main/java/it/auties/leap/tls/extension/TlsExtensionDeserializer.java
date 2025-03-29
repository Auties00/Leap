package it.auties.leap.tls.extension;

import it.auties.leap.tls.context.TlsContext;

import java.nio.ByteBuffer;
import java.util.Optional;

public interface TlsExtensionDeserializer {
    Optional<? extends TlsConfiguredExtension> deserialize(TlsContext context, int type, ByteBuffer buffer);
}
