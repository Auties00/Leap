package it.auties.leap.tls.extension.concrete;

import it.auties.leap.tls.config.TlsVersion;
import it.auties.leap.tls.extension.TlsExtension;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.Optional;

public final class PostHandshakeAuthExtension extends TlsExtension.Concrete {
    public static final PostHandshakeAuthExtension INSTANCE = new PostHandshakeAuthExtension();
    public static final int EXTENSION_TYPE = 0x0031;

    private PostHandshakeAuthExtension() {

    }

    public static Optional<PostHandshakeAuthExtension> of(TlsVersion version, ByteBuffer buffer, int extensionLength) {
        if(extensionLength != 0) {
            throw new IllegalArgumentException("Unexpected extension payload");
        }

        return Optional.of(INSTANCE);
    }

    @Override
    protected void serializeExtensionPayload(ByteBuffer buffer) {

    }

    @Override
    public int extensionPayloadLength() {
        return 0;
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
