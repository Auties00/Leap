package it.auties.leap.tls.extension.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.connection.TlsConnectionType;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.extension.TlsExtensionDependencies;
import it.auties.leap.tls.property.TlsProperty;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;

import static it.auties.leap.tls.util.BufferUtils.*;

public record ALPNExtension(
      List<String> supportedProtocols,
      int supportedProtocolsSize
) implements TlsExtension.Configured.Agnostic {
    public ALPNExtension(List<String> supportedProtocols) {
        var supportedProtocolsSources = new ArrayList<String>(supportedProtocols.size());
        var supportedProtocolsLength = 0;
        for(var supportedProtocol : supportedProtocols) {
            supportedProtocolsSources.add(supportedProtocol);
            supportedProtocolsLength += INT8_LENGTH + supportedProtocol.length();
        }
        this(supportedProtocolsSources, supportedProtocolsLength);
    }

    @Override
    public void serializePayload(ByteBuffer buffer) {
        writeBigEndianInt16(buffer, supportedProtocolsSize);
        for (var protocolName : supportedProtocols) {
            writeBytesBigEndian8(buffer, protocolName.getBytes(StandardCharsets.US_ASCII));
        }
    }

    @Override
    public int payloadLength() {
        return INT16_LENGTH + supportedProtocolsSize;
    }

    @Override
    public void apply(TlsContext context, TlsSource source) {
        var connection = switch (source) {
            case LOCAL -> context.localConnectionState();
            case REMOTE -> context.remoteConnectionState()
                    .orElseThrow(() -> new TlsAlert("No remote connection state was created", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR));
        };
        switch (connection.type()) {
            case CLIENT -> context.addNegotiableProperty(TlsProperty.applicationProtocols(), supportedProtocols);
            case SERVER -> context.addNegotiatedProperty(TlsProperty.applicationProtocols(), supportedProtocols);
        }
    }

    @Override
    public Optional<ALPNExtension> deserialize(TlsContext context, int type, ByteBuffer buffer) {
        var supportedProtocolsSize = readBigEndianInt16(buffer);
        var supportedProtocols = new ArrayList<String>();
        var negotiableProtocols = context.getNegotiableValue(TlsProperty.applicationProtocols())
                .orElseThrow(() -> new TlsAlert("Missing negotiable property: applicationProtocols", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR));
        var negotiableProtocolsSet = new HashSet<>(negotiableProtocols);
        var mode = context.localConnectionState().type();
        try(var _ = scopedRead(buffer, supportedProtocolsSize)) {
            while (buffer.hasRemaining()) {
                var supportedProtocol = new String(readBytesBigEndian8(buffer), StandardCharsets.US_ASCII);
                if(negotiableProtocolsSet.contains(supportedProtocol)) {
                    supportedProtocols.add(supportedProtocol);
                }else if(mode == TlsConnectionType.CLIENT) {
                    throw new TlsAlert("Remote tried to negotiate an application protocol that wasn't advertised", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
                }
            }
        }
        var extension = new ALPNExtension(supportedProtocols, supportedProtocolsSize);
        return Optional.of(extension);
    }

    @Override
    public int type() {
        return APPLICATION_LAYER_PROTOCOL_NEGOTIATION_TYPE;
    }

    @Override
    public List<TlsVersion> versions() {
        return APPLICATION_LAYER_PROTOCOL_NEGOTIATION_VERSIONS;
    }

    @Override
    public TlsExtensionDependencies dependencies() {
        return TlsExtensionDependencies.none();
    }
}
