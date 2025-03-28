package it.auties.leap.tls.extension.implementation.supportedVersions;

import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.extension.TlsConfiguredClientExtension;
import it.auties.leap.tls.extension.TlsExtensionDependencies;
import it.auties.leap.tls.extension.TlsExtensionDeserializer;
import it.auties.leap.tls.version.TlsVersion;
import it.auties.leap.tls.version.TlsVersionId;

import java.nio.ByteBuffer;
import java.util.List;

import static it.auties.leap.tls.util.BufferUtils.*;

record SupportedVersionsClientExtension(
        List<TlsVersionId> supportedVersions
) implements TlsConfiguredClientExtension {
    @Override
    public void serializePayload(ByteBuffer buffer) {
        var payloadSize = supportedVersions.size() * INT16_LENGTH;
        writeBigEndianInt8(buffer, payloadSize);
        for (var tlsVersion : supportedVersions) {
            writeBigEndianInt8(buffer, tlsVersion.major());
            writeBigEndianInt8(buffer, tlsVersion.minor());
        }
    }

    @Override
    public void apply(TlsContext context, TlsSource source) {

    }

    @Override
    public int payloadLength() {
        return INT8_LENGTH + INT16_LENGTH * supportedVersions.size();
    }

    @Override
    public int extensionType() {
        return SUPPORTED_VERSIONS_TYPE;
    }

    @Override
    public List<TlsVersion> versions() {
        return SUPPORTED_VERSIONS_VERSIONS;
    }

    public TlsExtensionDeserializer deserializer() {
        return SupportedVersionsExtensionDeserializer.INSTANCE;
    }

    @Override
    public TlsExtensionDependencies dependencies() {
        return TlsExtensionDependencies.none();
    }
}
