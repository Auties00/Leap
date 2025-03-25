package it.auties.leap.tls.extension.implementation;

import it.auties.leap.tls.TlsContext;
import it.auties.leap.tls.TlsSource;
import it.auties.leap.tls.TlsException;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.extension.TlsExtensionDeserializer;
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
) implements TlsExtension.Concrete {
    public ALPNExtension(List<String> supportedProtocols) {
        var supportedProtocolsSources = new ArrayList<String>(supportedProtocols.size());
        var supportedProtocolsLength = 0;
        for(var supportedProtocol : supportedProtocols) {
            supportedProtocolsSources.add(supportedProtocol);
            supportedProtocolsLength += INT8_LENGTH + supportedProtocol.length();
        }
        this(supportedProtocolsSources, supportedProtocolsLength);
    }

    private static final TlsExtensionDeserializer DECODER = (_, _, _, buffer) -> {
        var supportedProtocolsSize = readBigEndianInt16(buffer);
        var supportedProtocols = new ArrayList<String>();
        try(var _ = scopedRead(buffer, supportedProtocolsSize)) {
            while (buffer.hasRemaining()) {
                supportedProtocols.add(new String(readBytesBigEndian8(buffer), StandardCharsets.US_ASCII));
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
            case LOCAL -> context.setNegotiableProtocols(supportedProtocols);
            case REMOTE -> {
                var negotiableProtocols = new HashSet<>(context.negotiableProtocols());
                for(var supportedProtocol : supportedProtocols) {
                    if(!negotiableProtocols.contains(supportedProtocol)) {
                        throw new TlsException("Protocol %s was not negotiable".formatted(supportedProtocol));
                    }
                }
                context.setNegotiableProtocols(supportedProtocols);
            }
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
