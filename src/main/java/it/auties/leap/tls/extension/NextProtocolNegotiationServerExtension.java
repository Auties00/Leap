package it.auties.leap.tls.extension;

import it.auties.leap.tls.config.TlsVersion;

import java.nio.ByteBuffer;
import java.util.List;

import static it.auties.leap.tls.util.BufferHelper.writeBytesLittleEndian8;

public final class NextProtocolNegotiationServerExtension implements TlsExtension.Implementation {
    private final byte[] selectedProtocol;
    NextProtocolNegotiationServerExtension(byte[] selectedProtocol) {
        this.selectedProtocol = selectedProtocol;
    }

    @Override
    public void serializeExtensionPayload(ByteBuffer buffer) {
        writeBytesLittleEndian8(buffer, selectedProtocol);
    }

    @Override
    public int extensionPayloadLength() {
        return selectedProtocol.length;
    }

    @Override
    public int extensionType() {
        return TlsExtensions.NEXT_PROTOCOL_NEGOTIATION_TYPE;
    }

    @Override
    public List<TlsVersion> versions() {
        return TlsExtensions.NEXT_PROTOCOL_NEGOTIATION_VERSIONS;
    }

    public byte[] selectedProtocol() {
        return selectedProtocol;
    }
}
