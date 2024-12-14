package it.auties.leap.tls.extension.concrete;

import it.auties.leap.tls.TlsSupportedGroup;
import it.auties.leap.tls.TlsVersion;
import it.auties.leap.tls.extension.TlsConcreteExtension;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.Optional;

import static it.auties.leap.tls.TlsBuffer.*;

public final class KeyShareExtension extends TlsConcreteExtension {
    public static final int EXTENSION_TYPE = 0x0033;

    private final byte[] publicKey;
    private final TlsSupportedGroup namedGroup;
    public KeyShareExtension(byte[] publicKey, TlsSupportedGroup namedGroup) {
        this.publicKey = publicKey;
        this.namedGroup = namedGroup;
    }

    public static Optional<KeyShareExtension> of(TlsVersion version, ByteBuffer buffer, int extensionSize) {
        var namedGroupId = readLittleEndianInt16(buffer);
        var namedGroup = TlsSupportedGroup.of(namedGroupId)
                .orElseThrow(() -> new IllegalArgumentException("Unknown tls named group: " + namedGroupId));
        var publicKey = readBytesLittleEndian16(buffer);
        var extension = new KeyShareExtension(publicKey, namedGroup);
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
