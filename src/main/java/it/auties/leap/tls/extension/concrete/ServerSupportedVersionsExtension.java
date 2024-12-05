package it.auties.leap.tls.extension.concrete;

import it.auties.leap.tls.TlsVersion;
import it.auties.leap.tls.TlsVersionId;
import it.auties.leap.tls.extension.TlsConcreteExtension;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.Optional;

import static it.auties.leap.tls.TlsRecord.*;

public final class ServerSupportedVersionsExtension extends TlsConcreteExtension {
    public static final int EXTENSION_TYPE = 0x002B;

    private final TlsVersionId tlsVersion;
    public ServerSupportedVersionsExtension(TlsVersionId tlsVersion) {
        this.tlsVersion = tlsVersion;
    }


    public static Optional<ServerSupportedVersionsExtension> of(TlsVersion version, ByteBuffer buffer, int extensionLength) {
        var major = readInt8(buffer);
        var minor = readInt8(buffer);
        var versionId = new TlsVersionId(major, minor);
        var extension = new ServerSupportedVersionsExtension(versionId);
        return Optional.of(extension);
    }

    @Override
    protected void serializeExtensionPayload(ByteBuffer buffer) {
        writeInt8(buffer, tlsVersion.major());
        writeInt8(buffer, tlsVersion.minor());
    }

    @Override
    public int extensionPayloadLength() {
        return INT16_LENGTH;
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
