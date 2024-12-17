package it.auties.leap.tls.extension.concrete;

import it.auties.leap.tls.config.TlsIdentifiableUnion;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.key.TlsSupportedGroup;
import it.auties.leap.tls.config.TlsVersion;

import java.nio.ByteBuffer;
import java.util.*;

import static it.auties.leap.tls.BufferHelper.*;

public final class SupportedGroupsExtension extends TlsExtension.Concrete {
    public static final SupportedGroupsExtension RECOMMENDED = new SupportedGroupsExtension(List.of(
            TlsIdentifiableUnion.of(TlsSupportedGroup.x25519())
    ));
    public static final int EXTENSION_TYPE = 0x000A;

    private final List<? extends TlsIdentifiableUnion<TlsSupportedGroup, Integer>> groups;
    public SupportedGroupsExtension(List<? extends TlsIdentifiableUnion<TlsSupportedGroup, Integer>> groups) {
        this.groups = groups;
    }


    public static Optional<SupportedGroupsExtension> of(TlsVersion version, ByteBuffer buffer, int extensionLength) {
        var groupsSize = readLittleEndianInt16(buffer);
        var groups = new ArrayList<TlsIdentifiableUnion<TlsSupportedGroup, Integer>>(groupsSize);
        for(var i = 0; i < groupsSize; i++) {
            var groupId = readLittleEndianInt16(buffer);
            groups.add(TlsIdentifiableUnion.of(groupId));
        }
        var extension = new SupportedGroupsExtension(groups);
        return Optional.of(extension);
    }

    public List<? extends TlsIdentifiableUnion<TlsSupportedGroup, Integer>> groups() {
        return groups;
    }

    @Override
    protected void serializeExtensionPayload(ByteBuffer buffer) {
        var size = groups.size() * INT16_LENGTH;
        writeLittleEndianInt16(buffer, size);
        for(var ecPointFormat : groups) {
            writeLittleEndianInt16(buffer, ecPointFormat.id());
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
