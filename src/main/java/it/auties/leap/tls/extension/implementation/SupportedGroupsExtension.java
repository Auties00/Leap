package it.auties.leap.tls.extension.implementation;

import it.auties.leap.tls.TlsContext;
import it.auties.leap.tls.TlsMode;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.extension.TlsExtensionDeserializer;
import it.auties.leap.tls.key.TlsSupportedGroup;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import static it.auties.leap.tls.util.BufferUtils.*;

public abstract sealed class SupportedGroupsExtension {
    private static final TlsExtensionDeserializer DECODER = new TlsExtensionDeserializer() {
        @Override
        public Optional<? extends Concrete> deserialize(ByteBuffer buffer, int type, TlsMode mode) {
            var groupsSize = readLittleEndianInt16(buffer);
            var groups = new ArrayList<Integer>(groupsSize);
            for (var i = 0; i < groupsSize; i++) {
                var groupId = readLittleEndianInt16(buffer);
                groups.add(groupId);
            }
            var extension = new SupportedGroupsExtension.Concrete(groups);
            return Optional.of(extension);
        }

        @Override
        public Class<? extends Concrete> toConcreteType(TlsMode mode) {
            return SupportedGroupsExtension.Concrete.class;
        }
    };

    public static final class Concrete extends SupportedGroupsExtension implements TlsExtension.Concrete {
        private final List<Integer> groups;
        public Concrete(List<Integer> groups) {
            this.groups = groups;
        }

        public List<Integer> groups() {
            return groups;
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
        public TlsExtensionDeserializer decoder() {
            return DECODER;
        }

        @Override
        public boolean equals(Object obj) {
            if (obj == this) return true;
            if (obj == null || obj.getClass() != this.getClass()) return false;
            var that = (SupportedGroupsExtension.Concrete) obj;
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

    public static final class Configurable extends SupportedGroupsExtension implements TlsExtension.Configurable {
        private static final SupportedGroupsExtension.Configurable RECOMMENDED = new SupportedGroupsExtension.Configurable(List.of(TlsSupportedGroup.x25519()));

        private final List<TlsSupportedGroup> groups;
        public Configurable(List<TlsSupportedGroup> groups) {
            this.groups = groups;
        }

        public static TlsExtension recommended() {
            return RECOMMENDED;
        }

        public List<TlsSupportedGroup> groups() {
            return groups;
        }

        @Override
        public Optional<? extends TlsExtension.Concrete> newInstance(TlsContext context) {
            context.setSupportedGroups(groups);
            return Optional.of(new SupportedGroupsExtension.Concrete(groups.stream().map(TlsSupportedGroup::id).toList()));
        }

        @Override
        public Dependencies dependencies() {
            return Dependencies.none();
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
        public boolean equals(Object obj) {
            if (obj == this) return true;
            if (obj == null || obj.getClass() != this.getClass()) return false;
            var that = (SupportedGroupsExtension.Configurable) obj;
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
}
