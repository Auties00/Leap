package it.auties.leap.tls.extension.concrete;

import it.auties.leap.tls.config.TlsVersion;
import it.auties.leap.tls.extension.TlsExtension;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.Optional;

import static it.auties.leap.tls.BufferHelper.*;

public record PaddingExtension(int length) implements TlsExtension.Concrete {
    public static final int EXTENSION_TYPE = 0x0015;

    public static Optional<PaddingExtension> of(TlsVersion version, ByteBuffer buffer, int extensionLength) {
        var padding = readLittleEndianInt8(buffer);
        var extension = new PaddingExtension(padding);
        return Optional.of(extension);
    }

    @Override
    public void serializeExtensionPayload(ByteBuffer buffer) {
        for(var j = 0; j < length; j++) {
            buffer.put((byte) 0);
        }
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
