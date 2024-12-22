package it.auties.leap.tls.extension;

import it.auties.leap.tls.config.TlsVersion;

import java.nio.ByteBuffer;
import java.util.List;

import static it.auties.leap.tls.util.BufferHelper.INT16_LENGTH;
import static it.auties.leap.tls.util.BufferHelper.writeLittleEndianInt16;

public final class SupportedGroupsExtension implements TlsExtension.Implementation {
    private final List<Integer> groups;
    SupportedGroupsExtension(List<Integer> groups) {
        this.groups = groups;
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
        return TlsExtensions.SUPPORTED_GROUPS_TYPE;
    }

    @Override
    public List<TlsVersion> versions() {
        return TlsExtensions.SUPPORTED_GROUPS_VERSIONS;
    }

    public List<Integer> groups() {
        return groups;
    }

}
