package it.auties.leap.tls.extension.implementation.padding;

import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.extension.TlsExtensionDeserializer;

import java.nio.ByteBuffer;
import java.util.Optional;

import static it.auties.leap.tls.util.BufferUtils.readBigEndianInt8;

final class PaddingExtensionDeserializer implements TlsExtensionDeserializer {
    static final TlsExtensionDeserializer INSTANCE = new PaddingExtensionDeserializer();

    private PaddingExtensionDeserializer() {

    }

    @Override
    public Optional<? extends TlsExtension> deserialize(TlsContext context, int type, ByteBuffer buffer) {
        var padding = readBigEndianInt8(buffer);
        var extension = new PaddingExtension(padding);
        return Optional.of(extension);
    }
}
