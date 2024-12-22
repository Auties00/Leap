package it.auties.leap.tls.extension;

import it.auties.leap.tls.config.TlsVersion;
import it.auties.leap.tls.config.TlsVersionId;

import java.nio.ByteBuffer;
import java.util.List;

import static it.auties.leap.tls.util.BufferHelper.INT16_LENGTH;
import static it.auties.leap.tls.util.BufferHelper.writeLittleEndianInt8;

public final class SupportedVersionsServerExtension implements TlsExtension.Implementation {
    private final TlsVersionId tlsVersion;
    SupportedVersionsServerExtension(TlsVersionId tlsVersion) {
        this.tlsVersion = tlsVersion;
    }

    @Override
    public void serializeExtensionPayload(ByteBuffer buffer) {
        writeLittleEndianInt8(buffer, tlsVersion.major());
        writeLittleEndianInt8(buffer, tlsVersion.minor());
    }

    @Override
    public int extensionPayloadLength() {
        return INT16_LENGTH;
    }

    @Override
    public int extensionType() {
        return TlsExtensions.SUPPORTED_VERSIONS_TYPE;
    }

    @Override
    public List<TlsVersion> versions() {
        return TlsExtensions.SUPPORTED_VERSIONS_VERSIONS;
    }

    public TlsVersionId tlsVersion() {
        return tlsVersion;
    }
}
