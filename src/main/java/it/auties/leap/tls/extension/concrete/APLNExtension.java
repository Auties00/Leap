package it.auties.leap.tls.extension.concrete;

import it.auties.leap.tls.TlsVersion;
import it.auties.leap.tls.extension.TlsConcreteExtension;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static it.auties.leap.tls.TlsRecord.*;

public final class APLNExtension extends TlsConcreteExtension {
    public static final int EXTENSION_TYPE = 0x0010;

    private final List<byte[]> supportedProtocols;
    private final int supportedProtocolsSize;
    public APLNExtension(List<?> supportedProtocols) {
        var list = new ArrayList<byte[]>();
        var supportedProtocolsSize = 0;
        for (var entry : supportedProtocols) {
            switch (entry) {
                case String string -> {
                    var bytes = string.getBytes(StandardCharsets.US_ASCII);
                    supportedProtocolsSize += INT8_LENGTH + bytes.length;
                    list.add(bytes);
                }
                case byte[] bytes -> {
                    list.add(bytes);
                    supportedProtocolsSize += INT8_LENGTH + bytes.length;
                }
                default -> throw new IllegalArgumentException("Unexpected value: " + entry);
            }
        }
        this.supportedProtocols = list;
        this.supportedProtocolsSize = supportedProtocolsSize;
    }

    public static Optional<APLNExtension> of(TlsVersion version, ByteBuffer buffer, int extensionLength) {
        var supportedProtocolsSize = readInt16(buffer);
        var supportedProtocols = new ArrayList<byte[]>();
        try(var _ = scopedRead(buffer, supportedProtocolsSize)) {
            while (buffer.hasRemaining()) {
                supportedProtocols.add(readBytes8(buffer));
            }
        }
        var extension = new APLNExtension(supportedProtocols);
        return Optional.of(extension);
    }

    @Override
    protected void serializeExtensionPayload(ByteBuffer buffer) {
        writeInt16(buffer, supportedProtocolsSize);
        for(var protocolName : supportedProtocols) {
            writeBytes8(buffer, protocolName);
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
