package it.auties.leap.tls.extension.implementation.padding;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.extension.TlsConfiguredClientExtension;
import it.auties.leap.tls.extension.TlsConfiguredServerExtension;
import it.auties.leap.tls.extension.TlsExtensionDependencies;
import it.auties.leap.tls.extension.TlsExtensionDeserializer;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;
import java.util.List;

public record PaddingExtension(
        int length
) implements TlsConfiguredClientExtension, TlsConfiguredServerExtension {
    public PaddingExtension {
        if(length < 0) {
            throw new TlsAlert("Invalid negative padding length");
        }
    }

    @Override
    public void serializePayload(ByteBuffer buffer) {
        for (var j = 0; j < length; j++) {
            buffer.put((byte) 0);
        }
    }

    @Override
    public int payloadLength() {
        return length;
    }

    @Override
    public int extensionType() {
        return PADDING_TYPE;
    }

    @Override
    public void apply(TlsContext context, TlsSource source) {

    }

    @Override
    public List<TlsVersion> versions() {
        return PADDING_VERSIONS;
    }

    @Override
    public TlsExtensionDeserializer deserializer() {
        return PaddingExtensionDeserializer.INSTANCE;
    }

    @Override
    public TlsExtensionDependencies dependencies() {
        return TlsExtensionDependencies.all();
    }
}
