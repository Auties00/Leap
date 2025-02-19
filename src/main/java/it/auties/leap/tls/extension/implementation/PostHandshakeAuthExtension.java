package it.auties.leap.tls.extension.implementation;

import it.auties.leap.tls.context.TlsMode;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.extension.TlsExtensionDeserializer;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.Optional;

public final class PostHandshakeAuthExtension implements TlsExtension.Concrete {
    private static final PostHandshakeAuthExtension INSTANCE = new PostHandshakeAuthExtension();

    private static final TlsExtensionDeserializer DECODER = new TlsExtensionDeserializer(){
        @Override
        public Optional<? extends Concrete> deserialize(ByteBuffer buffer, int type, TlsMode mode) {
            if(buffer.hasRemaining()) {
                throw new IllegalArgumentException("Unexpected extension payload");
            }

            return Optional.of(PostHandshakeAuthExtension.instance());
        }

        @Override
        public Class<? extends Concrete> toConcreteType(TlsMode mode) {
            return PostHandshakeAuthExtension.class;
        }
    };

    private PostHandshakeAuthExtension() {

    }

    public static PostHandshakeAuthExtension instance() {
        return INSTANCE;
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
        return POST_HANDSHAKE_AUTH_TYPE;
    }

    @Override
    public List<TlsVersion> versions() {
        return POST_HANDSHAKE_AUTH_VERSIONS;
    }

    @Override
    public TlsExtensionDeserializer decoder() {
        return DECODER;
    }

    @Override
    public boolean equals(Object obj) {
        return obj == this || obj != null && obj.getClass() == this.getClass();
    }

    @Override
    public int hashCode() {
        return 1;
    }

    @Override
    public String toString() {
        return "PostHandshakeAuthExtension[]";
    }
}
