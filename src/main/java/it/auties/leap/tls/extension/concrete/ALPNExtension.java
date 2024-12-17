package it.auties.leap.tls.extension.concrete;

import it.auties.leap.tls.config.TlsVersion;
import it.auties.leap.tls.extension.TlsExtension;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static it.auties.leap.tls.BufferHelper.*;

public final class ALPNExtension extends TlsExtension.Concrete {
    public static final int EXTENSION_TYPE = 0x0010;

    private final List<byte[]> supportedProtocols;
    private final int supportedProtocolsSize;
    public ALPNExtension(List<byte[]> supportedProtocols) {
        this.supportedProtocols = supportedProtocols;
        this.supportedProtocolsSize = supportedProtocols.stream()
                .mapToInt(entry -> INT8_LENGTH + entry.length)
                .sum();
    }

    public static Optional<ALPNExtension> of(TlsVersion version, ByteBuffer buffer, int extensionLength) {
        var supportedProtocolsSize = readLittleEndianInt16(buffer);
        var supportedProtocols = new ArrayList<byte[]>();
        try(var _ = scopedRead(buffer, supportedProtocolsSize)) {
            while (buffer.hasRemaining()) {
                supportedProtocols.add(readBytesLittleEndian8(buffer));
            }
        }
        var extension = new ALPNExtension(supportedProtocols);
        return Optional.of(extension);
    }

    @Override
    protected void serializeExtensionPayload(ByteBuffer buffer) {
        writeLittleEndianInt16(buffer, supportedProtocolsSize);
        for(var protocolName : supportedProtocols) {
            writeBytesLittleEndian8(buffer, protocolName);
        }
    }

    @Override
    public int extensionPayloadLength() {
        return INT16_LENGTH + supportedProtocolsSize;
    }

    @Override
    public int extensionType() {
        return EXTENSION_TYPE;
    }

    @Override
    public List<TlsVersion> versions() {
        return List.of(TlsVersion.TLS12, TlsVersion.TLS13);
    }
}
