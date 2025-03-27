package it.auties.leap.tls.extension.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.extension.TlsConcreteExtension;
import it.auties.leap.tls.extension.TlsExtensionDeserializer;
import it.auties.leap.tls.property.TlsProperty;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.Optional;

public final class PostHandshakeAuthExtension implements TlsConcreteExtension {
    private static final TlsExtensionDeserializer DECODER = (_, _, _, buffer) -> {
        if(buffer.hasRemaining()) {
            throw new TlsAlert("Unexpected extension payload");
        }

        return Optional.of(PostHandshakeAuthExtension.INSTANCE);
    };

    private static final PostHandshakeAuthExtension INSTANCE = new PostHandshakeAuthExtension();

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
    public void apply(TlsContext context, TlsSource source) {
        switch (source) {
            case LOCAL -> context.addNegotiableProperty(TlsProperty.postHandshakeAuth(), true);
            case REMOTE -> context.addNegotiatedProperty(TlsProperty.postHandshakeAuth(), true);
        }
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
