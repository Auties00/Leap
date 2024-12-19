package it.auties.leap.tls.extension.concrete;

import it.auties.leap.tls.config.TlsVersion;
import it.auties.leap.tls.extension.TlsExtension;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.Optional;

import static it.auties.leap.tls.BufferHelper.readBytesLittleEndian8;
import static it.auties.leap.tls.BufferHelper.writeBytesLittleEndian8;

public record ServerNextProtocolNegotiationExtension(byte[] selectedProtocol) implements TlsExtension.Concrete {
    public static final int EXTENSION_TYPE = 0x3374;

    public static Optional<ServerNextProtocolNegotiationExtension> of(TlsVersion version, ByteBuffer buffer, int extensionLength) {
        var selectedProtocol = readBytesLittleEndian8(buffer);
        var extension = new ServerNextProtocolNegotiationExtension(selectedProtocol);
        return Optional.of(extension);
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
        return EXTENSION_TYPE;
    }

    @Override
    public List<TlsVersion> versions() {
        return List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13);
    }
}
