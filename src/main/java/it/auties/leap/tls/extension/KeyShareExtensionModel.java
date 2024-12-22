package it.auties.leap.tls.extension;

import it.auties.leap.tls.config.TlsMode;
import it.auties.leap.tls.config.TlsVersion;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.Optional;

import static it.auties.leap.tls.util.BufferHelper.*;

final class KeyShareExtensionModel implements TlsExtension.Model {
    static final KeyShareExtensionModel INSTANCE = new KeyShareExtensionModel();
    private KeyShareExtensionModel() {

    }

    @Override
    public Optional<? extends TlsExtension.Implementation> newInstance(Context context) {
        return Optional.empty();
    }

    @Override
    public Optional<? extends TlsExtension.Implementation> decode(ByteBuffer buffer, int type, TlsMode mode) {
        var namedGroupId = readLittleEndianInt16(buffer);
        var publicKey = readBytesLittleEndian16(buffer);
        var extension = new KeyShareExtension(publicKey, namedGroupId);
        return Optional.of(extension);
    }

    @Override
    public Class<? extends Implementation> toConcreteType(TlsMode mode) {
        return KeyShareExtension.class;
    }

    @Override
    public Dependencies dependencies() {
        return Dependencies.some(SupportedGroupsExtension.class);
    }

    @Override
    public int extensionType() {
        return TlsExtensions.KEY_SHARE_TYPE;
    }

    @Override
    public List<TlsVersion> versions() {
        return TlsExtensions.KEY_SHARE_VERSIONS;
    }

}
