package it.auties.leap.tls.extension.implementation;

import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.extension.TlsConfiguredClientExtension;
import it.auties.leap.tls.extension.TlsConfiguredServerExtension;
import it.auties.leap.tls.extension.TlsExtensionDependencies;
import it.auties.leap.tls.extension.TlsExtensionDeserializer;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.Optional;

import static it.auties.leap.tls.util.BufferUtils.readBytes;
import static it.auties.leap.tls.util.BufferUtils.writeBytes;

public record GREASEExtension(
        int extensionType,
        byte[] data
) implements TlsConfiguredClientExtension, TlsConfiguredServerExtension {
    private static final TlsExtensionDeserializer DESERIALIZER = (_, type, buffer) -> {
        var payload = buffer.hasRemaining() ? readBytes(buffer, buffer.remaining()) : null;
        var extension = new GREASEExtension(type, payload);
        return Optional.of(extension);
    };

    @Override
    public void serializePayload(ByteBuffer buffer) {
        if(data != null) {
            writeBytes(buffer, data);
        }
    }

    @Override
    public int payloadLength() {
        return 0;
    }

    @Override
    public void apply(TlsContext context, TlsSource source) {

    }

    @Override
    public List<TlsVersion> versions() {
        return GREASE_VERSIONS;
    }

    @Override
    public TlsExtensionDeserializer deserializer() {
        return DESERIALIZER;
    }

    @Override
    public TlsExtensionDependencies dependencies() {
        return TlsExtensionDependencies.none();
    }
}
