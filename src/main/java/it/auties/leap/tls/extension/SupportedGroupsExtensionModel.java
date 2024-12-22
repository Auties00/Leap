package it.auties.leap.tls.extension;

import it.auties.leap.tls.config.TlsMode;
import it.auties.leap.tls.config.TlsVersion;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static it.auties.leap.tls.util.BufferHelper.*;

final class SupportedGroupsExtensionModel implements TlsExtension.Model {
    @Override
    public Optional<? extends Implementation> newInstance(Context context) {
        return Optional.empty();
    }

    @Override
    public Optional<? extends Implementation> decode(ByteBuffer buffer, int type, TlsMode mode) {
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
    public Class<? extends Implementation> toConcreteType(TlsMode mode) {
        return SupportedGroupsExtension.class;
    }

    @Override
    public Dependencies dependencies() {
        return Dependencies.none();
    }

    @Override
    public int extensionType() {
        return TlsExtensions.SUPPORTED_GROUPS_TYPE;
    }

    @Override
    public List<TlsVersion> versions() {
        return TlsExtensions.SUPPORTED_GROUPS_VERSIONS;
    }
}
