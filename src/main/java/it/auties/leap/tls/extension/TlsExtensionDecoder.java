package it.auties.leap.tls.extension;

import it.auties.leap.tls.TlsMode;

import java.nio.ByteBuffer;
import java.util.Optional;

public interface TlsExtensionDecoder {
    Optional<? extends TlsExtension.Concrete> decode(ByteBuffer buffer, int type, TlsMode mode);

    Class<? extends TlsExtension.Concrete> toConcreteType(TlsMode mode);
}
