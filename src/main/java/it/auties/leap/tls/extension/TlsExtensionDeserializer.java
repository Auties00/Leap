package it.auties.leap.tls.extension;

import it.auties.leap.tls.TlsContext;
import it.auties.leap.tls.TlsSource;

import java.nio.ByteBuffer;
import java.util.Optional;

public interface TlsExtensionDeserializer {
    Optional<? extends TlsConcreteExtension> deserialize(TlsContext context, TlsSource source, int type, ByteBuffer buffer);
}
