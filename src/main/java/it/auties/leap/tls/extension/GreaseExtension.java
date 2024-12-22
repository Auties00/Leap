package it.auties.leap.tls.extension;

import it.auties.leap.tls.config.TlsVersion;

import java.nio.ByteBuffer;
import java.util.List;

public final class GreaseExtension implements TlsExtension.Implementation {
    private final int extensionType;
    GreaseExtension(int extensionType) {
        this.extensionType = extensionType;
    }

    @Override
    public void serializeExtensionPayload(ByteBuffer buffer) {

    }

    @Override
    public int extensionPayloadLength() {
        return 0;
    }

    @Override
    public int extensionType() {
        return extensionType;
    }

    @Override
    public List<TlsVersion> versions() {
        return TlsExtensions.GREASE_VERSIONS;
    }
}
