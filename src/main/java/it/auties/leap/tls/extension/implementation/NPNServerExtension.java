package it.auties.leap.tls.extension.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.extension.TlsExtensionDependencies;
import it.auties.leap.tls.extension.TlsExtensionDeserializer;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.property.TlsProperty;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;

import static it.auties.leap.tls.util.BufferUtils.INT8_LENGTH;
import static it.auties.leap.tls.util.BufferUtils.writeBytesBigEndian8;

public record NPNServerExtension(
        String selectedProtocol
) implements TlsExtension.Configured.Server {
    private static final TlsExtensionDeserializer<TlsExtension.Configured.Client> DESERIALIZER = (_, _, buffer) -> {
        if (buffer.hasRemaining()) {
            throw new TlsAlert("Unexpected extension payload");
        }

        return Optional.of(NPNClientExtension.instance());
    };

    @Override
    public void serializePayload(ByteBuffer buffer) {
        writeBytesBigEndian8(buffer, selectedProtocol.getBytes(StandardCharsets.US_ASCII));
    }

    @Override
    public int payloadLength() {
        return INT8_LENGTH + selectedProtocol.length();
    }

    @Override
    public void apply(TlsContext context, TlsSource source) {
        context.addNegotiatedProperty(TlsProperty.applicationProtocols(), List.of(selectedProtocol));
    }

    @Override
    public int extensionType() {
        return NEXT_PROTOCOL_NEGOTIATION_TYPE;
    }

    @Override
    public List<TlsVersion> versions() {
        return NEXT_PROTOCOL_NEGOTIATION_VERSIONS;
    }

    @Override
    public TlsExtensionDeserializer<TlsExtension.Configured.Client> deserializer() {
        return DESERIALIZER;
    }

    @Override
    public TlsExtensionDependencies dependencies() {
        return TlsExtensionDependencies.none();
    }
}
