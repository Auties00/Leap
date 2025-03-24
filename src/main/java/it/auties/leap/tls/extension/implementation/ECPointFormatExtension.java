package it.auties.leap.tls.extension.implementation;

import it.auties.leap.tls.TlsContext;
import it.auties.leap.tls.TlsSource;
import it.auties.leap.tls.ec.TlsECPointFormat;
import it.auties.leap.tls.exception.TlsException;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.extension.TlsExtensionDeserializer;
import it.auties.leap.tls.TlsIdentifiable;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;

import static it.auties.leap.tls.util.BufferUtils.*;

public record ECPointFormatExtension(
        List<Byte> ecPointFormats,
        int ecPointFormatsLength
) implements TlsExtension.Concrete {
    public ECPointFormatExtension(List<TlsECPointFormat> formats) {
        var ids = formats.stream()
                .map(TlsIdentifiable::id)
                .toList();
        var length = formats.size();
        this(ids, length);
    }

    private static final ECPointFormatExtension ALL = new ECPointFormatExtension(TlsECPointFormat.values());

    private static final TlsExtensionDeserializer DECODER = (_, _, _, buffer) -> {
        var ecPointFormatsLength = readBigEndianInt8(buffer);
        var ecPointFormats = new ArrayList<Byte>();
        for(var i = 0; i < ecPointFormatsLength; i++) {
            var ecPointFormatId = readBigEndianInt8(buffer);
            ecPointFormats.add(ecPointFormatId);
        }
        var extension = new ECPointFormatExtension(ecPointFormats, ecPointFormatsLength);
        return Optional.of(extension);
    };

    public static TlsExtension all() {
        return ALL;
    }

    @Override
    public void serializeExtensionPayload(ByteBuffer buffer) {
        writeBigEndianInt8(buffer, ecPointFormats.size());
        for (var ecPointFormat : ecPointFormats) {
            writeBigEndianInt8(buffer, ecPointFormat);
        }
    }

    @Override
    public int extensionPayloadLength() {
        return INT8_LENGTH + INT8_LENGTH * ecPointFormatsLength;
    }

    @Override
    public void apply(TlsContext context, TlsSource source) {
        switch (source) {
            case LOCAL -> context.setNegotiableProtocols(supportedProtocols);
            case REMOTE -> {
                var negotiableProtocols = new HashSet<>(context.negotiableProtocols());
                for(var supportedProtocol : supportedProtocols) {
                    if(!negotiableProtocols.contains(supportedProtocol)) {
                        throw new TlsException("Protocol %s was not negotiable".formatted(supportedProtocol));
                    }
                }
                context.setNegotiableProtocols(supportedProtocols);
            }
        }
    }

    @Override
    public int extensionType() {
        return EC_POINT_FORMATS_TYPE;
    }

    @Override
    public List<TlsVersion> versions() {
        return EC_POINT_FORMATS_VERSIONS;
    }

    @Override
    public TlsExtensionDeserializer decoder() {
        return DECODER;
    }
}
