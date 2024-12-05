package it.auties.leap.tls.extension.concrete;

import it.auties.leap.tls.TlsSupportedGroup;
import it.auties.leap.tls.TlsVersion;
import it.auties.leap.tls.extension.TlsConcreteExtension;

import java.nio.ByteBuffer;
import java.util.*;

import static it.auties.leap.tls.TlsRecord.*;

public final class SupportedGroupsExtension extends TlsConcreteExtension {
    public static final SupportedGroupsExtension RECOMMENDED = new SupportedGroupsExtension(TlsSupportedGroup.recommendedGroups());
    public static final int EXTENSION_TYPE = 0x000A;

    private final List<TlsSupportedGroup> groups;
    public SupportedGroupsExtension(List<TlsSupportedGroup> groups) {
        this.groups = groups.stream()
                .filter(Objects::nonNull)
                .toList();
        if(this.groups.isEmpty()) {
            throw new IllegalArgumentException("Named groups cannot be empty");
        }
    }

    public static Optional<SupportedGroupsExtension> of(TlsVersion version, ByteBuffer buffer, int extensionLength) {
        var groupsSize = readInt16(buffer);
        var groups = new ArrayList<TlsSupportedGroup>(groupsSize);
        for(var i = 0; i < groupsSize; i++) {
            var groupId = readInt16(buffer);
            var group = TlsSupportedGroup.of(groupId)
                    .orElseThrow(() -> new IllegalArgumentException("Unknown tls named group: " + groupId));
            groups.add(group);
        }
        var extension = new SupportedGroupsExtension(groups);
        return Optional.of(extension);
    }

    public List<TlsSupportedGroup> groups() {
        return groups;
    }

    public Optional<TlsSupportedGroup> preferredGroup() {
        return groups.isEmpty() ? Optional.empty() : Optional.ofNullable(groups.getFirst());
    }

    @Override
    protected void serializeExtensionPayload(ByteBuffer buffer) {
        var size = groups.size() * INT16_LENGTH;
        writeInt16(buffer, size);
        for(var ecPointFormat : groups) {
            writeInt16(buffer, ecPointFormat.id());
        }
    }

    @Override
    public int extensionPayloadLength() {
        return INT16_LENGTH + INT16_LENGTH * groups.size();
    }

    @Override
    public int extensionType() {
        return EXTENSION_TYPE;
    }

    @Override
    public List<TlsVersion> versions() {
        return List.of(TlsVersion.TLS12, TlsVersion.TLS13);
    }
}
