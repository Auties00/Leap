package it.auties.leap.tls.extension.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.extension.TlsExtensionDependencies;
import it.auties.leap.tls.property.TlsProperty;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.Optional;

public record ExtendedMasterSecretExtension(

) implements TlsExtension.Configured.Agnostic {
    private static final ExtendedMasterSecretExtension INSTANCE = new ExtendedMasterSecretExtension();

    public static TlsExtension.Configured.Agnostic instance() {
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
                    .orElseThrow(() -> new TlsAlert("No remote connection state was created", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR));
        };
        switch (connection.type()) {
            case CLIENT -> context.addNegotiableProperty(TlsProperty.extendedMasterSecret(), true);
            case SERVER -> context.addNegotiatedProperty(TlsProperty.extendedMasterSecret(), true);
        }
    }

    @Override
    public Optional<ExtendedMasterSecretExtension> deserialize(TlsContext context, int type, ByteBuffer buffer) {
        buffer.position(buffer.limit());
        return Optional.of(INSTANCE);
    }

    @Override
    public int type() {
        return EXTENDED_MASTER_SECRET_TYPE;
    }

    @Override
    public List<TlsVersion> versions() {
        return EXTENDED_MASTER_SECRET_VERSIONS;
    }

    @Override
    public TlsExtensionDependencies dependencies() {
        return TlsExtensionDependencies.none();
    }
}