package it.auties.leap.tls.extension.concrete;

import it.auties.leap.tls.TlsVersion;
import it.auties.leap.tls.extension.TlsConcreteExtension;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.Optional;

import static it.auties.leap.tls.TlsRecord.*;

public final class PaddingExtension extends TlsConcreteExtension {
    public static final int EXTENSION_TYPE = 0x0015;

    private final int length;
    public PaddingExtension(int length) {
        this.length = length;
    }

    public static Optional<PaddingExtension> of(TlsVersion version, ByteBuffer buffer, int extensionLength) {
        var padding = readInt8(buffer);
        var extension = new PaddingExtension(padding);
        return Optional.of(extension);
    }

    @Override
    protected void serializeExtensionPayload(ByteBuffer buffer) {
        writeInt8(buffer, 0, length);
    }

    @Override
    public int extensionPayloadLength() {
        return length;
    }

    @Override
    public int extensionType() {
        return EXTENSION_TYPE;
    }

    @Override
    public List<TlsVersion> versions() {
        return List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13);
    }
}
