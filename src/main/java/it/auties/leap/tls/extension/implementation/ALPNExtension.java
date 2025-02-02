package it.auties.leap.tls.extension.implementation;

import it.auties.leap.tls.TlsEngine;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.extension.TlsExtensionDecoder;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static it.auties.leap.tls.util.BufferUtils.*;

public record ALPNExtension(
      List<byte[]> supportedProtocols,
      int supportedProtocolsSize
) implements TlsExtension.Concrete {
    private static final TlsExtensionDecoder DECODER = new TlsExtensionDecoder() {
        @Override
        public Optional<? extends Concrete> decode(ByteBuffer buffer, int type, TlsEngine.Mode mode) {
            var supportedProtocolsSize = readLittleEndianInt16(buffer);
            var supportedProtocols = new ArrayList<byte[]>();
            try(var _ = scopedRead(buffer, supportedProtocolsSize)) {
                while (buffer.hasRemaining()) {
                    supportedProtocols.add(readBytesLittleEndian8(buffer));
                }
            }
            var extension = new ALPNExtension(supportedProtocols, supportedProtocolsSize);
            return Optional.of(extension);
        }

        @Override
        public Class<? extends Concrete> toConcreteType(TlsEngine.Mode mode) {
            return ALPNExtension.class;
        }
    };

    public static ALPNExtension of(List<String> supportedProtocols) {
        var supportedProtocolsSources = new ArrayList<byte[]>(supportedProtocols.size());
        var supportedProtocolsLength = 0;
        for(var supportedProtocol : supportedProtocols) {
            var source = supportedProtocol.getBytes(StandardCharsets.US_ASCII);
            supportedProtocolsSources.add(source);
            supportedProtocolsLength += INT8_LENGTH + source.length;
        }
        return new ALPNExtension(supportedProtocolsSources, supportedProtocolsLength);
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
        return APPLICATION_LAYER_PROTOCOL_NEGOTIATION_TYPE;
    }

    @Override
    public List<TlsVersion> versions() {
        return APPLICATION_LAYER_PROTOCOL_NEGOTIATION_VERSIONS;
    }

    @Override
    public TlsExtensionDecoder decoder() {
        return DECODER;
    }
}
