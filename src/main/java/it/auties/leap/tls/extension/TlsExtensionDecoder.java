package it.auties.leap.tls.extension;

import it.auties.leap.tls.TlsEngine;

import java.nio.ByteBuffer;
import java.util.Optional;

public interface TlsExtensionDecoder {
    Optional<? extends TlsExtension.Concrete> decode(ByteBuffer buffer, int type, TlsEngine.Mode mode);

    Class<? extends TlsExtension.Concrete> toConcreteType(TlsEngine.Mode mode);
}
