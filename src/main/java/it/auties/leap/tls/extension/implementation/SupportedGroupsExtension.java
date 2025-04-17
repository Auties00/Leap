package it.auties.leap.tls.extension.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.connection.TlsConnectionType;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.extension.TlsExtensionDependencies;
import it.auties.leap.tls.group.TlsSupportedEllipticCurve;
import it.auties.leap.tls.group.TlsSupportedFiniteField;
import it.auties.leap.tls.group.TlsSupportedGroup;
import it.auties.leap.tls.property.TlsIdentifiableProperty;
import it.auties.leap.tls.property.TlsProperty;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;

import static it.auties.leap.tls.util.BufferUtils.*;
import static it.auties.leap.tls.util.BufferUtils.readBigEndianInt16;

public record SupportedGroupsExtension(
        List<TlsSupportedGroup> groups
) implements TlsExtension.Configured.Agnostic {
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
        var connection = switch (source) {
            case LOCAL -> context.localConnectionState();
            case REMOTE -> context.remoteConnectionState()
                    .orElseThrow(() -> new TlsAlert("No remote connection state was created", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR));
        };
        switch (connection.type()) {
            case CLIENT -> context.addNegotiableProperty(TlsProperty.supportedGroups(), groups);
            case SERVER -> context.addNegotiatedProperty(TlsProperty.supportedGroups(), groups);
        }
    }

    @Override
    public Optional<SupportedGroupsExtension> deserialize(TlsContext context, int type, ByteBuffer buffer) {
        var groupsSize = readBigEndianInt16(buffer);
        var groups = new ArrayList<TlsSupportedGroup>(groupsSize);
        var knownGroups = context.getNegotiableValue(TlsProperty.supportedGroups())
                .orElseThrow(() -> new TlsAlert("Missing negotiable property: " + TlsProperty.ecPointsFormats().id(), TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR))
                .stream()
                .collect(Collectors.toUnmodifiableMap(TlsIdentifiableProperty::id, Function.identity()));
        var mode = context.localConnectionState().type();
        for (var i = 0; i < groupsSize; i++) {
            var groupId = readBigEndianInt16(buffer);
            var group = knownGroups.get(groupId);
            if(group != null) {
                groups.add(group);
            }else if(mode == TlsConnectionType.CLIENT) {
                throw new TlsAlert("Remote tried to negotiate a supported group that wasn't advertised", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
            }
        }
        var extension = new SupportedGroupsExtension(groups);
        return Optional.of(extension);
    }

    @Override
    public int type() {
        return SUPPORTED_GROUPS_TYPE;
    }

    @Override
    public List<TlsVersion> versions() {
        return SUPPORTED_GROUPS_VERSIONS;
    }

    @Override
    public TlsExtensionDependencies dependencies() {
        return TlsExtensionDependencies.none();
    }
}
