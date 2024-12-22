package it.auties.leap.tls.extension;

import it.auties.leap.tls.config.TlsVersion;

import java.nio.ByteBuffer;
import java.util.List;

import static it.auties.leap.tls.util.BufferHelper.*;

public final class KeyShareExtension implements TlsExtension.Implementation {
    private final byte[] publicKey;
    private final int namedGroup;
    KeyShareExtension(byte[] publicKey, int namedGroup) {
        this.publicKey = publicKey;
        this.namedGroup = namedGroup;
    }

    @Override
    public void serializeExtensionPayload(ByteBuffer buffer) {
        var size = INT16_LENGTH + INT16_LENGTH + publicKey.length;
        writeLittleEndianInt16(buffer, size);
        writeLittleEndianInt16(buffer, namedGroup);
        writeBytesLittleEndian16(buffer, publicKey);
    }

    @Override
    public int extensionPayloadLength() {
        return INT16_LENGTH + INT16_LENGTH + INT16_LENGTH + publicKey.length;
    }

    @Override
    public int extensionType() {
        return TlsExtensions.KEY_SHARE_TYPE;
    }

    @Override
    public List<TlsVersion> versions() {
        return TlsExtensions.KEY_SHARE_VERSIONS;
    }

    public byte[] publicKey() {
        return publicKey;
    }

    public int namedGroup() {
        return namedGroup;
    }
}
