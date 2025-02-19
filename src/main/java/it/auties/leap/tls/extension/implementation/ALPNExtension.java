package it.auties.leap.tls.extension.implementation;

import it.auties.leap.tls.context.TlsMode;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.extension.TlsExtensionDeserializer;
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
    private static final TlsExtensionDeserializer DECODER = new TlsExtensionDeserializer() {
        @Override
        public Optional<? extends Concrete> deserialize(ByteBuffer buffer, int type, TlsMode mode) {
            var supportedProtocolsSize = readBigEndianInt16(buffer);
            var supportedProtocols = new ArrayList<byte[]>();
            try(var _ = scopedRead(buffer, supportedProtocolsSize)) {
                while (buffer.hasRemaining()) {
                    supportedProtocols.add(readBytesBigEndian8(buffer));
                }
            }
            var extension = new ALPNExtension(supportedProtocols, supportedProtocolsSize);
            return Optional.of(extension);
        }

        @Override
        public Class<? extends Concrete> toConcreteType(TlsMode mode) {
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
        writeBigEndianInt16(buffer, supportedProtocolsSize);
        for (var protocolName : supportedProtocols) {
            writeBytesBigEndian8(buffer, protocolName);
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
    public TlsExtensionDeserializer decoder() {
        return DECODER;
    }
}
