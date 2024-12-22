package it.auties.leap.tls.extension;

import it.auties.leap.tls.config.TlsVersion;

import java.nio.ByteBuffer;
import java.util.List;

public final class NextProtocolNegotiationClientExtension implements TlsExtension.Implementation {
    static final NextProtocolNegotiationClientExtension INSTANCE = new NextProtocolNegotiationClientExtension();
    private NextProtocolNegotiationClientExtension() {

    }

    @Override
    public void serializeExtensionPayload(ByteBuffer buffer) {

    }

    @Override
    public int extensionPayloadLength() {
        return 0;
    }

    @Override
    public int extensionType() {
        return TlsExtensions.NEXT_PROTOCOL_NEGOTIATION_TYPE;
    }

    @Override
    public List<TlsVersion> versions() {
        return TlsExtensions.NEXT_PROTOCOL_NEGOTIATION_VERSIONS;
    }
}
