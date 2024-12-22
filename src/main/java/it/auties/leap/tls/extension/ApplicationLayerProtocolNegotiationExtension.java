package it.auties.leap.tls.extension;

import it.auties.leap.tls.config.TlsVersion;

import java.nio.ByteBuffer;
import java.util.List;

import static it.auties.leap.tls.util.BufferHelper.*;

public final class ApplicationLayerProtocolNegotiationExtension implements TlsExtension.Implementation {
    private final List<byte[]> supportedProtocols;
    private final int supportedProtocolsSize;
    ApplicationLayerProtocolNegotiationExtension(List<byte[]> supportedProtocols, int supportedProtocolsSize) {
        this.supportedProtocols = supportedProtocols;
        this.supportedProtocolsSize = supportedProtocolsSize;
    }

    ApplicationLayerProtocolNegotiationExtension(List<byte[]> supportedProtocols) {
        this(supportedProtocols, lengthOf(supportedProtocols));
    }

    private static int lengthOf(List<byte[]> supportedProtocols) {
        return supportedProtocols.stream()
                .mapToInt(entry -> INT8_LENGTH + entry.length)
                .sum();
    }

    @Override
    public void serializeExtensionPayload(ByteBuffer buffer) {
        writeLittleEndianInt16(buffer, supportedProtocolsSize);
        for (var protocolName : supportedProtocols) {
            writeBytesLittleEndian8(buffer, protocolName);
        }
    }

    @Override
    public int extensionPayloadLength() {
        return INT16_LENGTH + supportedProtocolsSize;
    }

    @Override
    public int extensionType() {
        return TlsExtensions.APPLICATION_LAYER_PROTOCOL_NEGOTIATION_TYPE;
    }

    @Override
    public List<TlsVersion> versions() {
        return TlsExtensions.APPLICATION_LAYER_PROTOCOL_NEGOTIATION_VERSIONS;
    }

    public List<byte[]> supportedProtocols() {
        return supportedProtocols;
    }

    public int supportedProtocolsSize() {
        return supportedProtocolsSize;
    }
}
