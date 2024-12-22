package it.auties.leap.tls.extension;

import it.auties.leap.tls.config.TlsVersion;

import java.nio.ByteBuffer;
import java.util.List;

public final class PaddingExtension implements TlsExtension.Implementation {
    private final int length;
    PaddingExtension(int length) {
        this.length = length;
    }

    @Override
    public void serializeExtensionPayload(ByteBuffer buffer) {
        for (var j = 0; j < length; j++) {
            buffer.put((byte) 0);
        }
    }

    @Override
    public int extensionPayloadLength() {
        return length;
    }

    @Override
    public int extensionType() {
        return TlsExtensions.PADDING_TYPE;
    }

    @Override
    public List<TlsVersion> versions() {
        return TlsExtensions.PADDING_VERSIONS;
    }

    public int length() {
        return length;
    }
}
