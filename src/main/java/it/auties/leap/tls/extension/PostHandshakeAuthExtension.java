package it.auties.leap.tls.extension;

import it.auties.leap.tls.config.TlsVersion;

import java.nio.ByteBuffer;
import java.util.List;

public final class PostHandshakeAuthExtension implements TlsExtension.Implementation {
    static final PostHandshakeAuthExtension INSTANCE = new PostHandshakeAuthExtension();
    private PostHandshakeAuthExtension() {

    }


    @Override
    public void serializeExtensionPayload(ByteBuffer buffer) {

    }

    @Override
    public int extensionPayloadLength() {
        return 0;
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
