package it.auties.leap.tls.extension.implementation;

import it.auties.leap.tls.TlsContext;
import it.auties.leap.tls.TlsMode;
import it.auties.leap.tls.TlsSource;
import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.extension.TlsConcreteExtension;
import it.auties.leap.tls.extension.TlsExtensionDeserializer;
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
) implements TlsConcreteExtension {
    public ALPNExtension(List<String> supportedProtocols) {
        var supportedProtocolsSources = new ArrayList<String>(supportedProtocols.size());
        var supportedProtocolsLength = 0;
        for(var supportedProtocol : supportedProtocols) {
            supportedProtocolsSources.add(supportedProtocol);
            supportedProtocolsLength += INT8_LENGTH + supportedProtocol.length();
        }
        this(supportedProtocolsSources, supportedProtocolsLength);
    }

    private static final TlsExtensionDeserializer DECODER = (context, source, _, buffer) -> {
        var supportedProtocolsSize = readBigEndianInt16(buffer);
        var supportedProtocols = new ArrayList<String>();
        var negotiableProtocols = context.getNegotiableValue(TlsProperty.applicationProtocols())
                .orElseThrow(() -> TlsAlert.noNegotiableProperty(TlsProperty.applicationProtocols()));
        var negotiableProtocolsSet = new HashSet<>(negotiableProtocols);
        var mode = context.selectedMode()
                .orElseThrow(TlsAlert::noModeSelected);
        var incomingToClient = mode == TlsMode.CLIENT && source == TlsSource.REMOTE;
        try(var _ = scopedRead(buffer, supportedProtocolsSize)) {
            while (buffer.hasRemaining()) {
                var supportedProtocol = new String(readBytesBigEndian8(buffer), StandardCharsets.US_ASCII);
                if(negotiableProtocolsSet.contains(supportedProtocol)) {
                    supportedProtocols.add(supportedProtocol);
                }else if(incomingToClient) {
                    throw new TlsAlert("Remote tried to negotiate an application protocol that wasn't advertised");
                }
            }
        }
        var extension = new ALPNExtension(supportedProtocols, supportedProtocolsSize);
        return Optional.of(extension);
    };

    @Override
    public void serializeExtensionPayload(ByteBuffer buffer) {
        writeBigEndianInt16(buffer, supportedProtocolsSize);
        for (var protocolName : supportedProtocols) {
            writeBytesBigEndian8(buffer, protocolName.getBytes(StandardCharsets.US_ASCII));
        }
    }

    @Override
    public int extensionPayloadLength() {
        return INT16_LENGTH + supportedProtocolsSize;
    }

    @Override
    public void apply(TlsContext context, TlsSource source) {
        switch (source) {
            case LOCAL -> context.addNegotiableProperty(TlsProperty.applicationProtocols(), supportedProtocols);
            case REMOTE -> context.addNegotiatedProperty(TlsProperty.applicationProtocols(), supportedProtocols);
        }
    }

    @Override
    public int extensionType() {
        return APPLICATION_LAYER_PROTOCOL_NEGOTIATION_TYPE;
    }

    @Override
    public List<TlsVersion> versions() {
        return APPLICATION_LAYER_PROTOCOL_NEGOTIATION_VERSIONS;
    }

    @Override
    public TlsExtensionDeserializer decoder() {
        return DECODER;
    }
}
