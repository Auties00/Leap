package it.auties.leap.tls.extension;

import it.auties.leap.tls.config.TlsMode;
import it.auties.leap.tls.config.TlsVersion;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.Optional;

final class PostHandshakeAuthExtensionModel implements TlsExtension.Model {
    @Override
    public Optional<? extends Implementation> newInstance(Context context) {
        return Optional.of(PostHandshakeAuthExtension.INSTANCE);
    }

    @Override
    public Optional<? extends Implementation> decode(ByteBuffer buffer, int type, TlsMode mode) {
        if (buffer.hasRemaining()) {
            throw new IllegalArgumentException("Unexpected extension payload");
        }

        return Optional.of(PostHandshakeAuthExtension.INSTANCE);
    }

    @Override
    public Class<? extends Implementation> toConcreteType(TlsMode mode) {
        return PostHandshakeAuthExtension.class;
    }

    @Override
    public Dependencies dependencies() {
        return Dependencies.none();
    }

    @Override
    public int extensionType() {
        return TlsExtensions.POST_HANDSHAKE_AUTH_TYPE;
    }

    @Override
    public List<TlsVersion> versions() {
        return TlsExtensions.POST_HANDSHAKE_AUTH_VERSIONS;
    }
}
