package it.auties.leap.tls.extension.implementation;

import it.auties.leap.tls.TlsEngine;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.extension.TlsExtensionDecoder;
import it.auties.leap.tls.key.TlsSupportedGroup;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import static it.auties.leap.tls.util.BufferUtils.*;
import static it.auties.leap.tls.util.BufferUtils.readLittleEndianInt16;

public record SupportedGroupsExtension(
        List<Integer> groups
) implements TlsExtension.Concrete {
    private static final TlsExtensionDecoder DECODER = new TlsExtensionDecoder() {
        @Override
        public Optional<? extends Concrete> decode(ByteBuffer buffer, int type, TlsEngine.Mode mode) {
            var groupsSize = readLittleEndianInt16(buffer);
            var groups = new ArrayList<Integer>(groupsSize);
            for (var i = 0; i < groupsSize; i++) {
                var groupId = readLittleEndianInt16(buffer);
                groups.add(groupId);
            }
            var extension = new SupportedGroupsExtension(groups);
            return Optional.of(extension);
        }

        @Override
        public Class<? extends Concrete> toConcreteType(TlsEngine.Mode mode) {
            return SupportedGroupsExtension.class;
        }
    };

    private static final SupportedGroupsExtension RECOMMENDED = new SupportedGroupsExtension(List.of(
            TlsSupportedGroup.x25519().id()
    ));

    public static SupportedGroupsExtension of(List<TlsSupportedGroup> supportedGroups) {
        return new SupportedGroupsExtension(supportedGroups.stream()
                .map(TlsSupportedGroup::id)
                .toList());
    }

    public static TlsExtension recommended() {
        return RECOMMENDED;
    }

    @Override
    public void serializeExtensionPayload(ByteBuffer buffer) {
        var size = groups.size() * INT16_LENGTH;
        writeLittleEndianInt16(buffer, size);
        for (var ecPointFormat : groups) {
            writeLittleEndianInt16(buffer, ecPointFormat);
        }
    }

    @Override
    public int extensionPayloadLength() {
        return INT16_LENGTH + INT16_LENGTH * groups.size();
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
    public TlsExtensionDecoder decoder() {
        return DECODER;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == this) return true;
        if (obj == null || obj.getClass() != this.getClass()) return false;
        var that = (SupportedGroupsExtension) obj;
        return Objects.equals(this.groups, that.groups);
    }

    @Override
    public int hashCode() {
        return Objects.hash(groups);
    }

    @Override
    public String toString() {
        return "SupportedGroupsExtension[" +
                "groups=" + groups + ']';
    }
}
