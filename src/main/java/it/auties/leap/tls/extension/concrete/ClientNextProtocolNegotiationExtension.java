package it.auties.leap.tls.extension.concrete;

import it.auties.leap.tls.config.TlsVersion;
import it.auties.leap.tls.extension.TlsExtension;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.Optional;

public final class ClientNextProtocolNegotiationExtension extends TlsExtension.Concrete {
    public static final ClientNextProtocolNegotiationExtension INSTANCE = new ClientNextProtocolNegotiationExtension();
    public static final int EXTENSION_TYPE = 0x3374;

    private ClientNextProtocolNegotiationExtension() {

    }

    public static Optional<ClientNextProtocolNegotiationExtension> of(TlsVersion version, ByteBuffer buffer, int extensionLength) {
        if(extensionLength != 0) {
            throw new IllegalArgumentException("Unexpected extension payload");
        }

        return Optional.of(INSTANCE);
    }

    @Override
    protected void serializeExtensionPayload(ByteBuffer buffer) {

    }

    @Override
    public int extensionPayloadLength() {
        return 0;
    }

    @Override
    public int extensionType() {
        return EXTENSION_TYPE;
    }

    @Override
    public List<TlsVersion> versions() {
        return List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13);
    }
}
