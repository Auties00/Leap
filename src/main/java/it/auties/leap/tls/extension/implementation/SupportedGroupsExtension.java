package it.auties.leap.tls.extension.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsContextMode;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.extension.TlsConcreteExtension;
import it.auties.leap.tls.extension.TlsExtensionDeserializer;
import it.auties.leap.tls.group.TlsSupportedEllipticCurve;
import it.auties.leap.tls.group.TlsSupportedFiniteField;
import it.auties.leap.tls.group.TlsSupportedGroup;
import it.auties.leap.tls.property.TlsIdentifiableProperty;
import it.auties.leap.tls.property.TlsProperty;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;

import static it.auties.leap.tls.util.BufferUtils.*;

public final class SupportedGroupsExtension implements TlsConcreteExtension {
    private static final TlsExtensionDeserializer DECODER = (context, source, _, buffer) -> {
        var groupsSize = readBigEndianInt16(buffer);
        var groups = new ArrayList<TlsSupportedGroup>(groupsSize);
        var knownGroups = context.getNegotiableValue(TlsProperty.supportedGroups())
                .orElseThrow(() -> TlsAlert.noNegotiableProperty(TlsProperty.ecPointsFormats()))
                .stream()
                .collect(Collectors.toUnmodifiableMap(TlsIdentifiableProperty::id, Function.identity()));
        var mode = context.selectedMode()
                .orElseThrow(TlsAlert::noModeSelected);
        var incomingToClient = mode == TlsContextMode.CLIENT && source == TlsSource.REMOTE;
        for (var i = 0; i < groupsSize; i++) {
            var groupId = readBigEndianInt16(buffer);
            var group = knownGroups.get(groupId);
            if(group != null) {
                groups.add(group);
            }else if(incomingToClient) {
                throw new TlsAlert("Remote tried to negotiate a supported group that wasn't advertised");
            }
        }
        var extension = new SupportedGroupsExtension(groups);
        return Optional.of(extension);
    };

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

    private final List<TlsSupportedGroup> groups;
    public SupportedGroupsExtension(List<TlsSupportedGroup> groups) {
        this.groups = groups;
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
    public TlsExtensionDeserializer decoder() {
        return DECODER;
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof SupportedGroupsExtension concrete
                && Objects.equals(groups, concrete.groups);
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(groups);
    }

    @Override
    public String toString() {
        return "SupportedGroupsExtension[" +
                "groups=" + groups + ']';
    }
}
