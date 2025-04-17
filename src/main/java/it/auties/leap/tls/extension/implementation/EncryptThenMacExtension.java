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

public record EncryptThenMacExtension(

) implements TlsExtension.Configured.Agnostic {
    private static final EncryptThenMacExtension INSTANCE = new EncryptThenMacExtension();

    public static EncryptThenMacExtension instance() {
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
            case CLIENT -> context.addNegotiableProperty(TlsProperty.encryptThenMac(), true);
            case SERVER -> context.addNegotiatedProperty(TlsProperty.encryptThenMac(), true);
        }
    }

    @Override
    public Optional<EncryptThenMacExtension> deserialize(TlsContext context, int type, ByteBuffer buffer) {
        if (buffer.hasRemaining()) {
            throw new TlsAlert("Unexpected extension payload", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
        }

        return Optional.of(INSTANCE);
    }

    @Override
    public int type() {
        return ENCRYPT_THEN_MAC_TYPE;
    }

    @Override
    public List<TlsVersion> versions() {
        return ENCRYPT_THEN_MAC_VERSIONS;
    }

    @Override
    public TlsExtensionDependencies dependencies() {
        return TlsExtensionDependencies.none();
    }
}
