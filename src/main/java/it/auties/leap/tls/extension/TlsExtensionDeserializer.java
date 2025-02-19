package it.auties.leap.tls.extension;

import it.auties.leap.tls.context.TlsMode;

import java.nio.ByteBuffer;
import java.util.Optional;

public interface TlsExtensionDeserializer {
    Optional<? extends TlsExtension.Concrete> deserialize(ByteBuffer buffer, int type, TlsMode mode);

    Class<? extends TlsExtension.Concrete> toConcreteType(TlsMode mode);
}
