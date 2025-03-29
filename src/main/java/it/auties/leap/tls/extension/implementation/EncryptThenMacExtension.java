package it.auties.leap.tls.extension.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.extension.TlsConfiguredClientExtension;
import it.auties.leap.tls.extension.TlsConfiguredServerExtension;
import it.auties.leap.tls.extension.TlsExtensionDependencies;
import it.auties.leap.tls.extension.TlsExtensionDeserializer;
import it.auties.leap.tls.property.TlsProperty;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.Optional;

public record EncryptThenMacExtension(

) implements TlsConfiguredClientExtension, TlsConfiguredServerExtension {
    private static final TlsExtensionDeserializer DESERIALIZER = (_, _, buffer) -> {
        if (buffer.hasRemaining()) {
            throw new TlsAlert("Unexpected extension payload");
        }

        return Optional.of(EncryptThenMacExtension.INSTANCE);
    };

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
        switch (source) {
            case LOCAL -> context.addNegotiableProperty(TlsProperty.encryptThenMac(), true);
            case REMOTE -> context.addNegotiatedProperty(TlsProperty.encryptThenMac(), true);
        }
    }

    @Override
    public int extensionType() {
        return ENCRYPT_THEN_MAC_TYPE;
    }

    @Override
    public List<TlsVersion> versions() {
        return ENCRYPT_THEN_MAC_VERSIONS;
    }

    @Override
    public TlsExtensionDeserializer deserializer() {
        return DESERIALIZER;
    }

    @Override
    public TlsExtensionDependencies dependencies() {
        return TlsExtensionDependencies.none();
    }
}
