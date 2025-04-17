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

public record TruncatedHmacExtension(

) implements TlsExtension.Configured.Agnostic {
    private static final TruncatedHmacExtension INSTANCE = new TruncatedHmacExtension();

    public static Agnostic instance() {
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
            case CLIENT -> context.addNegotiableProperty(TlsProperty.truncatedHmac(), true);
            case SERVER -> context.addNegotiatedProperty(TlsProperty.truncatedHmac(), true);
        }
    }

    @Override
    public Optional<TruncatedHmacExtension> deserialize(TlsContext context, int type, ByteBuffer buffer) {
        buffer.position(buffer.limit());
        return Optional.of(INSTANCE);
    }

    @Override
    public int type() {
        return TRUNCATED_HMAC_TYPE;
    }

    @Override
    public List<TlsVersion> versions() {
        return TRUNCATED_HMAC_VERSIONS;
    }

    @Override
    public TlsExtensionDependencies dependencies() {
        return TlsExtensionDependencies.none();
    }
}