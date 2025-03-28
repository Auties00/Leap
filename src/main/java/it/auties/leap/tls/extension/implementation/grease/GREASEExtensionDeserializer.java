package it.auties.leap.tls.extension.implementation.grease;

import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.extension.TlsExtensionDeserializer;

import java.nio.ByteBuffer;
import java.util.Optional;

import static it.auties.leap.tls.util.BufferUtils.readBytes;

final class GREASEExtensionDeserializer implements TlsExtensionDeserializer {
    static final TlsExtensionDeserializer INSTANCE = new GREASEExtensionDeserializer();

    private GREASEExtensionDeserializer() {

    }

    @Override
    public Optional<? extends TlsExtension> deserialize(TlsContext context, int type, ByteBuffer buffer) {
        var payload = buffer.hasRemaining() ? readBytes(buffer, buffer.remaining()) : null;
        var extension = new GREASEExtension(type, payload);
        return Optional.of(extension);
    }
}
