package it.auties.leap.tls.extension.concrete;

import it.auties.leap.tls.config.TlsIdentifiableUnion;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.key.TlsSupportedGroup;
import it.auties.leap.tls.config.TlsVersion;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.Optional;

import static it.auties.leap.tls.BufferHelper.*;

public final class KeyShareExtension extends TlsExtension.Concrete {
    public static final int EXTENSION_TYPE = 0x0033;

    private final byte[] publicKey;
    private final TlsIdentifiableUnion<TlsSupportedGroup, Integer> namedGroup;
    public KeyShareExtension(byte[] publicKey, TlsIdentifiableUnion<TlsSupportedGroup, Integer> namedGroup) {
        this.publicKey = publicKey;
        this.namedGroup = namedGroup;
    }

    public static Optional<KeyShareExtension> of(TlsVersion version, ByteBuffer buffer, int extensionSize) {
        var namedGroupId = readLittleEndianInt16(buffer);
        var publicKey = readBytesLittleEndian16(buffer);
        var extension = new KeyShareExtension(publicKey, TlsIdentifiableUnion.of(namedGroupId));
        return Optional.of(extension);
    }

    @Override
    protected void serializeExtensionPayload(ByteBuffer buffer) {
        var size = INT16_LENGTH + INT16_LENGTH + publicKey.length;
        writeLittleEndianInt16(buffer, size);
        writeLittleEndianInt16(buffer, namedGroup.id());
        writeBytesLittleEndian16(buffer, publicKey);
    }

    @Override
    public int extensionPayloadLength() {
        return INT16_LENGTH + INT16_LENGTH + INT16_LENGTH + publicKey.length;
    }

    @Override
    public int extensionType() {
        return EXTENSION_TYPE;
    }

    @Override
    public List<TlsVersion> versions() {
        return List.of(TlsVersion.TLS13);
    }
}
