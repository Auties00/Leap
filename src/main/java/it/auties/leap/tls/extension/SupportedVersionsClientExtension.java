package it.auties.leap.tls.extension;

import it.auties.leap.tls.config.TlsVersion;
import it.auties.leap.tls.config.TlsVersionId;

import java.nio.ByteBuffer;
import java.util.List;

import static it.auties.leap.tls.util.BufferHelper.*;

public final class SupportedVersionsClientExtension implements TlsExtension.Implementation {
    private final List<TlsVersionId> tlsVersions;
    SupportedVersionsClientExtension(List<TlsVersionId> tlsVersions) {
        this.tlsVersions = tlsVersions;
    }

    @Override
    public void serializeExtensionPayload(ByteBuffer buffer) {
        var payloadSize = tlsVersions.size() * INT16_LENGTH;
        writeLittleEndianInt8(buffer, payloadSize);
        for (var tlsVersion : tlsVersions) {
            writeLittleEndianInt8(buffer, tlsVersion.major());
            writeLittleEndianInt8(buffer, tlsVersion.minor());
        }
    }

    @Override
    public int extensionPayloadLength() {
        return INT8_LENGTH + INT16_LENGTH * tlsVersions.size();
    }

    @Override
    public int extensionType() {
        return TlsExtensions.SUPPORTED_VERSIONS_TYPE;
    }

    @Override
    public List<TlsVersion> versions() {
        return TlsExtensions.SUPPORTED_VERSIONS_VERSIONS;
    }

    public List<TlsVersionId> tlsVersions() {
        return tlsVersions;
    }
}
