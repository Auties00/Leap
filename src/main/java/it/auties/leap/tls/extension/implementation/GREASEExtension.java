package it.auties.leap.tls.extension.implementation;

import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.extension.TlsConcreteExtension;
import it.auties.leap.tls.extension.TlsExtensionDeserializer;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import static it.auties.leap.tls.util.BufferUtils.readBytes;
import static it.auties.leap.tls.util.BufferUtils.writeBytes;

public record GREASEExtension(int extensionType, byte[] data) implements TlsConcreteExtension {
    private static final TlsExtensionDeserializer DECODER = (_, _, type, buffer) -> {
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
    public TlsExtensionDeserializer decoder() {
        return DECODER;
    }

    @Override
    public boolean equals(Object obj) {
        return obj instanceof GREASEExtension(int extensionType, byte[] data)
                && this.extensionType == extensionType
                && Arrays.equals(this.data, data);
    }

    @Override
    public int hashCode() {
        return Objects.hash(extensionType);
    }

    @Override
    public String toString() {
        return "GREASEExtension[" +
                "type=" + extensionType +
                ", data=" + Arrays.toString(data) +
                ']';
    }
}
