package it.auties.leap.tls.extension.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsContextualProperty;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.extension.TlsExtensionDependencies;
import it.auties.leap.tls.extension.TlsExtensionPayload;
import it.auties.leap.tls.group.TlsSupportedEllipticCurve;
import it.auties.leap.tls.group.TlsSupportedFiniteField;
import it.auties.leap.tls.group.TlsSupportedGroup;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;

import static it.auties.leap.tls.util.BufferUtils.*;

public record SupportedGroupsExtension(
        List<TlsSupportedGroup> groups
) implements TlsExtension.Agnostic, TlsExtensionPayload {
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
    public TlsExtensionPayload toPayload(TlsContext context) {
        return this;
    }

    @Override
    public void apply(TlsContext context, TlsSource source) {
        var connection = switch (source) {
            case LOCAL -> context.localConnectionState();
            case REMOTE -> context.remoteConnectionState()
                    .orElseThrow(() -> new TlsAlert("No remote connection state was created", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR));
        };
        switch (connection.type()) {
            case CLIENT -> context.addAdvertisedValue(TlsContextualProperty.supportedGroups(), groups);
            case SERVER -> context.addNegotiatedValue(TlsContextualProperty.supportedGroups(), groups);
        }
    }

    @Override
    public Optional<SupportedGroupsExtension> deserializeClient(TlsContext context, int type, ByteBuffer source) {
        return deserialize(context, source);
    }

    @Override
    public Optional<SupportedGroupsExtension> deserializeServer(TlsContext context, int type, ByteBuffer source) {
        return deserialize(context, source);
    }

    private Optional<SupportedGroupsExtension> deserialize(TlsContext context, ByteBuffer buffer) {
        var groupsSize = readBigEndianInt16(buffer);
        var knownGroups = context.getAdvertisedValue(TlsContextualProperty.supportedGroups())
                .orElseThrow(() -> new TlsAlert("Missing negotiable property: supportedGroups", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR))
                .stream()
                .collect(Collectors.toUnmodifiableMap(TlsSupportedGroup::id, Function.identity()));
        var groups = new ArrayList<TlsSupportedGroup>(groupsSize);
        try(var _ = scopedRead(buffer, groupsSize)) {
            while(buffer.hasRemaining()) {
                var groupId = readBigEndianInt16(buffer);
                var group = knownGroups.get(groupId);
                if(group != null) {
                    groups.add(group);
                }
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
