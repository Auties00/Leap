package it.auties.leap.tls.extension.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.extension.*;
import it.auties.leap.tls.property.TlsProperty;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.Optional;

public record ExtendedMasterSecretExtension(

) implements TlsConfiguredClientExtension, TlsConfiguredServerExtension {
    private static final TlsExtensionDeserializer DESERIALIZER = (_, _, buffer) -> {
        if (buffer.hasRemaining()) {
            throw new TlsAlert("Unexpected extension payload");
        }

        return Optional.of(ExtendedMasterSecretExtension.INSTANCE);
    };

    static final ExtendedMasterSecretExtension INSTANCE = new ExtendedMasterSecretExtension();

    public static TlsExtension instance() {
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
            case LOCAL -> context.addNegotiableProperty(TlsProperty.extendedMasterSecret(), true);
            case REMOTE -> context.addNegotiatedProperty(TlsProperty.extendedMasterSecret(), true);
        }
    }

    @Override
    public int extensionType() {
        return EXTENDED_MASTER_SECRET_TYPE;
    }

    @Override
    public List<TlsVersion> versions() {
        return EXTENDED_MASTER_SECRET_VERSIONS;
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