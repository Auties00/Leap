package it.auties.leap.tls.extension.concrete;

import it.auties.leap.tls.config.TlsVersion;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.key.TlsSupportedGroup;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static it.auties.leap.tls.BufferHelper.*;

public record SupportedGroupsExtension(List<Integer> groups) implements TlsExtension.Concrete {
    public static final SupportedGroupsExtension RECOMMENDED = new SupportedGroupsExtension(List.of(
            TlsSupportedGroup.x25519().id()
    ));
    public static final int EXTENSION_TYPE = 0x000A;


    public static Optional<SupportedGroupsExtension> of(TlsVersion version, ByteBuffer buffer, int extensionLength) {
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
        return EXTENSION_TYPE;
    }

    @Override
    public List<TlsVersion> versions() {
        return List.of(TlsVersion.TLS12, TlsVersion.TLS13);
    }
}
