package it.auties.leap.tls.extension;

import it.auties.leap.tls.config.TlsVersion;

import java.nio.ByteBuffer;
import java.util.List;

public final class ExtendedMasterSecretExtension implements TlsExtension.Implementation {
    static final ExtendedMasterSecretExtension INSTANCE = new ExtendedMasterSecretExtension();
    private ExtendedMasterSecretExtension() {

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
        return TlsExtensions.EXTENDED_MASTER_SECRET_TYPE;
    }

    @Override
    public List<TlsVersion> versions() {
        return TlsExtensions.EXTENDED_MASTER_SECRET_VERSIONS;
    }
}
