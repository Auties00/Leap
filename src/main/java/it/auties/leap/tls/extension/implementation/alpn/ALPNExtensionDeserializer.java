package it.auties.leap.tls.extension.implementation.alpn;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsContextMode;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.extension.TlsExtensionDeserializer;
import it.auties.leap.tls.property.TlsProperty;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Optional;

import static it.auties.leap.tls.util.BufferUtils.*;

final class ALPNExtensionDeserializer implements TlsExtensionDeserializer {
    static final TlsExtensionDeserializer INSTANCE = new ALPNExtensionDeserializer();

    private ALPNExtensionDeserializer() {

    }

    @Override
    public Optional<? extends TlsExtension> deserialize(TlsContext context, int type, ByteBuffer buffer) {
        var supportedProtocolsSize = readBigEndianInt16(buffer);
        var supportedProtocols = new ArrayList<String>();
        var negotiableProtocols = context.getNegotiableValue(TlsProperty.applicationProtocols())
                .orElseThrow(() -> TlsAlert.noNegotiableProperty(TlsProperty.applicationProtocols()));
        var negotiableProtocolsSet = new HashSet<>(negotiableProtocols);
        var mode = context.selectedMode()
                .orElseThrow(TlsAlert::noModeSelected);
        try(var _ = scopedRead(buffer, supportedProtocolsSize)) {
            while (buffer.hasRemaining()) {
                var supportedProtocol = new String(readBytesBigEndian8(buffer), StandardCharsets.US_ASCII);
                if(negotiableProtocolsSet.contains(supportedProtocol)) {
                    supportedProtocols.add(supportedProtocol);
                }else if(mode == TlsContextMode.CLIENT) {
                    throw new TlsAlert("Remote tried to negotiate an application protocol that wasn't advertised");
                }
            }
        }
        var extension = new ALPNExtension(supportedProtocols, supportedProtocolsSize);
        return Optional.of(extension);
    }
}
