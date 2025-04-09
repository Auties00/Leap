package it.auties.leap.tls.extension.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.extension.TlsExtensionDependencies;
import it.auties.leap.tls.property.TlsProperty;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.Optional;

public record PostHandshakeAuthExtension(

) implements TlsExtension.Configured.Agnostic {
    private static final PostHandshakeAuthExtension INSTANCE = new PostHandshakeAuthExtension();

    public static PostHandshakeAuthExtension instance() {
        return INSTANCE;
    }

    @Override
    public void serializePayload(ByteBuffer buffer) {

    }

    @Override
    public int payloadLength() {
        return 0;
    }

    @Override
    public void apply(TlsContext context, TlsSource source) {
        var connection = switch (source) {
            case LOCAL -> context.localConnectionState();
            case REMOTE -> context.remoteConnectionState()
                    .orElseThrow(TlsAlert::noRemoteConnectionState);
        };
        switch (connection.type()) {
            case CLIENT -> context.addNegotiableProperty(TlsProperty.postHandshakeAuth(), true);
            case SERVER -> context.addNegotiatedProperty(TlsProperty.postHandshakeAuth(), true);
        }
    }

    @Override
    public Optional<PostHandshakeAuthExtension> deserialize(TlsContext context, int type, ByteBuffer buffer) {
        buffer.position(buffer.limit());
        return Optional.of(INSTANCE);
    }

    @Override
    public int type() {
        return POST_HANDSHAKE_AUTH_TYPE;
    }

    @Override
    public List<TlsVersion> versions() {
        return POST_HANDSHAKE_AUTH_VERSIONS;
    }

    @Override
    public TlsExtensionDependencies dependencies() {
        return TlsExtensionDependencies.none();
    }
}
