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
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;

import static it.auties.leap.tls.util.BufferUtils.INT8_LENGTH;
import static it.auties.leap.tls.util.BufferUtils.writeBytesBigEndian8;

public record NPNServerExtension(
        String selectedProtocol
) implements TlsExtension.Configured.Server {
    @Override
    public void serializePayload(ByteBuffer buffer) {
        writeBytesBigEndian8(buffer, selectedProtocol.getBytes(StandardCharsets.US_ASCII));
    }

    @Override
    public int payloadLength() {
        return INT8_LENGTH + selectedProtocol.length();
    }

    @Override
    public int type() {
        return NEXT_PROTOCOL_NEGOTIATION_TYPE;
    }

    @Override
    public List<TlsVersion> versions() {
        return NEXT_PROTOCOL_NEGOTIATION_VERSIONS;
    }

    @Override
    public void apply(TlsContext context, TlsSource source) {
        var connection = switch (source) {
            case LOCAL -> context.localConnectionState();
            case REMOTE -> context.remoteConnectionState()
                    .orElseThrow(() -> new TlsAlert("No remote connection state was created", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR));
        };
        switch (connection.type()) {
            case CLIENT -> context.addNegotiableProperty(TlsProperty.applicationProtocols(), List.of(selectedProtocol));
            case SERVER -> context.addNegotiatedProperty(TlsProperty.applicationProtocols(), List.of(selectedProtocol));
        }
    }

    @Override
    public Optional<NPNClientExtension> deserialize(TlsContext context, int type, ByteBuffer buffer) {
        buffer.position(buffer.limit());
        return Optional.of(NPNClientExtension.instance());
    }

    @Override
    public TlsExtensionDependencies dependencies() {
        return TlsExtensionDependencies.none();
    }
}
