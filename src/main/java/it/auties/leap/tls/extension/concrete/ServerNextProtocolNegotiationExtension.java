package it.auties.leap.tls.extension.concrete;

import it.auties.leap.tls.TlsVersion;
import it.auties.leap.tls.extension.TlsConcreteExtension;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;

import static it.auties.leap.tls.TlsBuffer.*;

public final class ServerNextProtocolNegotiationExtension extends TlsConcreteExtension {
    public static final int EXTENSION_TYPE = 0x3374;

    private final byte[] selectedProtocol;
    public ServerNextProtocolNegotiationExtension(String selectedProtocol) {
        this.selectedProtocol = selectedProtocol.getBytes(StandardCharsets.US_ASCII);
    }

    public ServerNextProtocolNegotiationExtension(byte[] selectedProtocol) {
        this.selectedProtocol = selectedProtocol;
    }

    public byte[] selectedProtocol() {
        return selectedProtocol;
    }

    public static Optional<ServerNextProtocolNegotiationExtension> of(TlsVersion version, ByteBuffer buffer, int extensionLength) {
        var selectedProtocol = readBytesLittleEndian8(buffer);
        var extension = new ServerNextProtocolNegotiationExtension(selectedProtocol);
        return Optional.of(extension);
    }

    @Override
    protected void serializeExtensionPayload(ByteBuffer buffer) {
        writeBytesLittleEndian8(buffer, selectedProtocol);
    }

    @Override
    public int extensionPayloadLength() {
        return selectedProtocol.length;
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
