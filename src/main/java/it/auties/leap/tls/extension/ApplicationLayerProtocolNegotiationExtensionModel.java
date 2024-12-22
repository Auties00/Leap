package it.auties.leap.tls.extension;

import it.auties.leap.tls.config.TlsMode;
import it.auties.leap.tls.config.TlsVersion;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static it.auties.leap.tls.util.BufferHelper.*;

public final class ApplicationLayerProtocolNegotiationExtensionModel implements TlsExtension.Model {
    @Override
    public Optional<? extends TlsExtension.Implementation> newInstance(Context context) {
        return Optional.empty();
    }

    @Override
    public Optional<? extends TlsExtension.Implementation> decode(ByteBuffer buffer, int type, TlsMode mode) {
        var supportedProtocolsSize = readLittleEndianInt16(buffer);
        var supportedProtocols = new ArrayList<byte[]>();
        try(var _ = scopedRead(buffer, supportedProtocolsSize)) {
            while (buffer.hasRemaining()) {
                supportedProtocols.add(readBytesLittleEndian8(buffer));
            }
        }
        var extension = new ApplicationLayerProtocolNegotiationExtension(supportedProtocols, supportedProtocolsSize);
        return Optional.of(extension);
    }

    @Override
    public Class<? extends Implementation> toConcreteType(TlsMode mode) {
        return ApplicationLayerProtocolNegotiationExtension.class;
    }

    @Override
    public Dependencies dependencies() {
        return Dependencies.none();
    }

    @Override
    public int extensionType() {
        return TlsExtensions.APPLICATION_LAYER_PROTOCOL_NEGOTIATION_TYPE;
    }

    @Override
    public List<TlsVersion> versions() {
        return TlsExtensions.APPLICATION_LAYER_PROTOCOL_NEGOTIATION_VERSIONS;
    }
}
