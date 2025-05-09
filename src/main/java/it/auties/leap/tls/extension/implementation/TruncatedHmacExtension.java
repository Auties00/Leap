package it.auties.leap.tls.extension.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.extension.TlsExtensionDependencies;
import it.auties.leap.tls.context.TlsContextualProperty;
import it.auties.leap.tls.extension.TlsExtensionPayload;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.Optional;

public final class TruncatedHmacExtension implements TlsExtension.Agnostic, TlsExtensionPayload {
    private static final TruncatedHmacExtension INSTANCE = new TruncatedHmacExtension();

    private TruncatedHmacExtension() {

    }

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
    public TlsExtensionPayload toPayload(TlsContext context) {
        return this;
    }

    @Override
    public void apply(TlsContext context, TlsSource source) {
        var connection = switch (source) {
            case LOCAL -> context.localConnectionState();
            case REMOTE -> context.remoteConnectionState()
                    .orElseThrow(() -> new TlsAlert("No remote connection state was created", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR));
        };
        switch (connection.type()) {
            case CLIENT -> context.addAdvertisedValue(TlsContextualProperty.truncatedHmac(), true);
            case SERVER -> context.addNegotiatedValue(TlsContextualProperty.truncatedHmac(), true);
        }
    }

    @Override
    public Optional<TruncatedHmacExtension> deserializeClient(TlsContext context, int type, ByteBuffer source) {
        return deserialize(source);
    }

    @Override
    public Optional<TruncatedHmacExtension> deserializeServer(TlsContext context, int type, ByteBuffer source) {
        return deserialize(source);
    }

    private Optional<TruncatedHmacExtension> deserialize(ByteBuffer buffer) {
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

    @Override
    public int hashCode() {
        return type();
    }

    @Override
    public String toString() {
        return "TruncatedHmacExtension[]";
    }
}