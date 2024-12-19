package it.auties.leap.tls.extension.concrete;

import it.auties.leap.tls.config.TlsVersion;
import it.auties.leap.tls.config.TlsVersionId;
import it.auties.leap.tls.extension.TlsExtension;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static it.auties.leap.tls.BufferHelper.*;

public record ClientSupportedVersionsExtension(List<TlsVersionId> tlsVersions) implements TlsExtension.Concrete {
    public static final int EXTENSION_TYPE = 0x002B;

    public static Optional<ClientSupportedVersionsExtension> of(TlsVersion version, ByteBuffer buffer, int extensionLength) {
        var payloadSize = readLittleEndianInt8(buffer);
        var versions = new ArrayList<TlsVersionId>();
        try (var _ = scopedRead(buffer, payloadSize)) {
            var versionsSize = payloadSize / INT16_LENGTH;
            for (var i = 0; i < versionsSize; i++) {
                var versionId = TlsVersionId.of(readLittleEndianInt8(buffer), readLittleEndianInt8(buffer));
                versions.add(versionId);
            }
        }
        var extension = new ClientSupportedVersionsExtension(versions);
        return Optional.of(extension);
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
        return EXTENSION_TYPE;
    }

    @Override
    public List<TlsVersion> versions() {
        return List.of(TlsVersion.TLS13);
    }
}
