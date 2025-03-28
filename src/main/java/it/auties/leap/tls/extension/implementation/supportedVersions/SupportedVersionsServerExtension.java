package it.auties.leap.tls.extension.implementation.supportedVersions;

import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.extension.TlsConfiguredServerExtension;
import it.auties.leap.tls.extension.TlsExtensionDependencies;
import it.auties.leap.tls.extension.TlsExtensionDeserializer;
import it.auties.leap.tls.property.TlsProperty;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;
import java.util.List;

import static it.auties.leap.tls.util.BufferUtils.INT16_LENGTH;
import static it.auties.leap.tls.util.BufferUtils.writeBigEndianInt8;

record SupportedVersionsServerExtension(
        TlsVersion version
) implements TlsConfiguredServerExtension {
    @Override
    public void serializePayload(ByteBuffer buffer) {
        writeBigEndianInt8(buffer, version.id().major());
        writeBigEndianInt8(buffer, version.id().minor());
    }

    @Override
    public int payloadLength() {
        return INT16_LENGTH;
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
    public void apply(TlsContext context, TlsSource source) {
        context.addNegotiatedProperty(TlsProperty.version(), version);
    }

    @Override
    public TlsExtensionDependencies dependencies() {
        return TlsExtensionDependencies.none();
    }
}
