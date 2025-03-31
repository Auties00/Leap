package it.auties.leap.tls.extension.implementation;

import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.extension.TlsExtensionDependencies;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.Optional;

import static it.auties.leap.tls.util.BufferUtils.readBytes;
import static it.auties.leap.tls.util.BufferUtils.writeBytes;

public record GREASEExtension(
        int type,
        byte[] data
) implements TlsExtension.Configured.Agnostic {
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
    public List<TlsVersion> versions() {
        return GREASE_VERSIONS;
    }

    @Override
    public void apply(TlsContext context, TlsSource source) {

    }

    @Override
    public Optional<GREASEExtension> deserialize(TlsContext context, int type, ByteBuffer buffer) {
        var payload = buffer.hasRemaining() ? readBytes(buffer, buffer.remaining()) : null;
        var extension = new GREASEExtension(type, payload);
        return Optional.of(extension);
    }

    @Override
    public TlsExtensionDependencies dependencies() {
        return TlsExtensionDependencies.none();
    }
}
