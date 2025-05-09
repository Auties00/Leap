package it.auties.leap.tls.extension.implementation;

import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.extension.TlsExtensionDependencies;
import it.auties.leap.tls.extension.TlsExtensionPayload;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.Optional;

import static it.auties.leap.tls.util.BufferUtils.readBytes;
import static it.auties.leap.tls.util.BufferUtils.writeBytes;

public record GREASEExtension(
        int type,
        byte[] data
) implements TlsExtension.Agnostic, TlsExtensionPayload {
    @Override
    public void serializePayload(ByteBuffer buffer) {
        if(data != null) {
            writeBytes(buffer, data);
        }
    }

    @Override
    public int payloadLength() {
        return data == null ? 0 : data.length;
    }

    @Override
    public TlsExtensionPayload toPayload(TlsContext context) {
        return this;
    }

    @Override
    public List<TlsVersion> versions() {
        return GREASE_VERSIONS;
    }

    @Override
    public void apply(TlsContext context, TlsSource source) {

    }

    @Override
    public Optional<GREASEExtension> deserializeClient(TlsContext context, int type, ByteBuffer source) {
        return deserialize(type, source);
    }

    @Override
    public Optional<? extends Client> deserializeServer(TlsContext context, int type, ByteBuffer source) {
        return deserialize(type, source);
    }

    private Optional<GREASEExtension> deserialize(int responseType, ByteBuffer response) {
        var payload = response.hasRemaining() ? readBytes(response, response.remaining()) : null;
        var extension = new GREASEExtension(responseType, payload);
        return Optional.of(extension);
    }

    @Override
    public TlsExtensionDependencies dependencies() {
        return TlsExtensionDependencies.none();
    }
}
