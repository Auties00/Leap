package it.auties.leap.tls.extension.implementation.supportedGroups;

import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.extension.TlsConfiguredClientExtension;
import it.auties.leap.tls.extension.TlsConfiguredServerExtension;
import it.auties.leap.tls.extension.TlsExtensionDependencies;
import it.auties.leap.tls.extension.TlsExtensionDeserializer;
import it.auties.leap.tls.group.TlsSupportedEllipticCurve;
import it.auties.leap.tls.group.TlsSupportedFiniteField;
import it.auties.leap.tls.group.TlsSupportedGroup;
import it.auties.leap.tls.property.TlsProperty;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;
import java.util.List;

import static it.auties.leap.tls.util.BufferUtils.INT16_LENGTH;
import static it.auties.leap.tls.util.BufferUtils.writeBigEndianInt16;

public record SupportedGroupsExtension(
        List<TlsSupportedGroup> groups
) implements TlsConfiguredClientExtension, TlsConfiguredServerExtension {
    private static final SupportedGroupsExtension RECOMMENDED = new SupportedGroupsExtension(List.of(
            TlsSupportedEllipticCurve.x25519(),
            TlsSupportedEllipticCurve.x448(),
            TlsSupportedFiniteField.ffdhe2048(),
            TlsSupportedFiniteField.ffdhe3072(),
            TlsSupportedFiniteField.ffdhe4096(),
            TlsSupportedFiniteField.ffdhe6144(),
            TlsSupportedFiniteField.ffdhe8192()
    ));

    public static SupportedGroupsExtension recommended() {
        return RECOMMENDED;
    }

    @Override
    public void serializePayload(ByteBuffer buffer) {
        var size = groups.size() * INT16_LENGTH;
        writeBigEndianInt16(buffer, size);
        for (var ecPointFormat : groups) {
            writeBigEndianInt16(buffer, ecPointFormat.id());
        }
    }

    @Override
    public int payloadLength() {
        return INT16_LENGTH + INT16_LENGTH * groups.size();
    }

    @Override
    public void apply(TlsContext context, TlsSource source) {
        switch (source) {
            case LOCAL -> context.addNegotiableProperty(TlsProperty.supportedGroups(), groups);
            case REMOTE -> context.addNegotiatedProperty(TlsProperty.supportedGroups(), groups);
        }
    }

    @Override
    public int extensionType() {
        return SUPPORTED_GROUPS_TYPE;
    }

    @Override
    public List<TlsVersion> versions() {
        return SUPPORTED_GROUPS_VERSIONS;
    }

    @Override
    public TlsExtensionDeserializer deserializer() {
        return SupportedGroupsExtensionDeserializer.INSTANCE;
    }

    @Override
    public TlsExtensionDependencies dependencies() {
        return TlsExtensionDependencies.none();
    }
}
