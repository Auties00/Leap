package it.auties.leap.tls.extension;

import it.auties.leap.tls.context.TlsMode;
import it.auties.leap.tls.context.TlsSource;

import java.nio.ByteBuffer;
import java.util.Optional;

public interface TlsExtensionDeserializer {
    Optional<? extends TlsExtension.Concrete> deserialize(ByteBuffer buffer, TlsSource source, TlsMode mode, int type);

    Class<? extends TlsExtension.Concrete> toConcreteType(TlsSource source, TlsMode mode);
}
