package it.auties.leap.tls.extension.implementation;

import it.auties.leap.tls.TlsContext;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.extension.TlsExtensionDeserializer;
import it.auties.leap.tls.group.TlsSupportedEllipticCurve;
import it.auties.leap.tls.group.TlsSupportedFiniteField;
import it.auties.leap.tls.group.TlsSupportedGroup;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import static it.auties.leap.tls.util.BufferUtils.*;

public abstract sealed class SupportedGroupsExtension {
    private static final TlsExtensionDeserializer DECODER = (_, _, _, buffer) -> {
        var groupsSize = readBigEndianInt16(buffer);
        var groups = new ArrayList<Integer>(groupsSize);
        for (var i = 0; i < groupsSize; i++) {
            var groupId = readBigEndianInt16(buffer);
            groups.add(groupId);
        }
        var extension = new Concrete(groups);
        return Optional.of(extension);
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
            writeBigEndianInt16(buffer, size);
            for (var ecPointFormat : groups) {
                writeBigEndianInt16(buffer, ecPointFormat);
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
        private static final List<TlsSupportedGroup> RECOMMENDED_GROUPS = List.of(
                TlsSupportedEllipticCurve.x25519(),
                TlsSupportedEllipticCurve.x448(),
                TlsSupportedFiniteField.ffdhe2048(),
                TlsSupportedFiniteField.ffdhe3072(),
                TlsSupportedFiniteField.ffdhe4096(),
                TlsSupportedFiniteField.ffdhe6144(),
                TlsSupportedFiniteField.ffdhe8192()
        );
        private static final SupportedGroupsExtension.Configurable RECOMMENDED = new SupportedGroupsExtension.Configurable(RECOMMENDED_GROUPS);

        private final List<TlsSupportedGroup> groups;
        public Configurable(List<TlsSupportedGroup> groups) {
            this.groups = groups;
        }

        public static TlsExtension recommended() {
            return RECOMMENDED;
        }

        public static List<TlsSupportedGroup> recommendedGroups() {
            return RECOMMENDED_GROUPS;
        }

        public List<TlsSupportedGroup> groups() {
            return groups;
        }

        @Override
        public Optional<? extends TlsExtension.Concrete> newInstance(TlsContext context) {
            context.setLocalSupportedGroups(groups);
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
