package it.auties.leap.tls.extension;

import it.auties.leap.tls.config.TlsVersion;

import java.nio.ByteBuffer;
import java.util.List;

public final class EncryptThenMacExtension implements TlsExtension.Implementation {
    static final EncryptThenMacExtension INSTANCE = new EncryptThenMacExtension();
    private EncryptThenMacExtension() {

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
        return TlsExtensions.ENCRYPT_THEN_MAC_TYPE;
    }

    @Override
    public List<TlsVersion> versions() {
        return TlsExtensions.ENCRYPT_THEN_MAC_VERSIONS;
    }
}
