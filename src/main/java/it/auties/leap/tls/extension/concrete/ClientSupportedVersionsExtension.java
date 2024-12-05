package it.auties.leap.tls.extension.concrete;

import it.auties.leap.tls.TlsVersion;
import it.auties.leap.tls.TlsVersionId;
import it.auties.leap.tls.extension.TlsConcreteExtension;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static it.auties.leap.tls.TlsRecord.*;

public final class ClientSupportedVersionsExtension extends TlsConcreteExtension {
    public static final int EXTENSION_TYPE = 0x002B;

    private final List<TlsVersionId> tlsVersions;
    public ClientSupportedVersionsExtension(List<TlsVersionId> tlsVersions) {
        this.tlsVersions = tlsVersions;
    }

    public static Optional<ClientSupportedVersionsExtension> of(TlsVersion version, ByteBuffer buffer, int extensionLength) {
        var payloadSize = readInt8(buffer);
        var versions = new ArrayList<TlsVersionId>();
        try(var _ = scopedRead(buffer, payloadSize)) {
            var versionsSize = payloadSize / INT16_LENGTH;
            for(var i = 0; i < versionsSize; i++) {
                var versionId = new TlsVersionId(readInt8(buffer), readInt8(buffer));
                versions.add(versionId);
            }
        }
        var extension = new ClientSupportedVersionsExtension(versions);
        return Optional.of(extension);
    }

    @Override
    protected void serializeExtensionPayload(ByteBuffer buffer) {
        var payloadSize = tlsVersions.size() * INT16_LENGTH;
        writeInt8(buffer, payloadSize);
        for(var tlsVersion : tlsVersions) {
            writeInt8(buffer, tlsVersion.major());
            writeInt8(buffer, tlsVersion.minor());
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
