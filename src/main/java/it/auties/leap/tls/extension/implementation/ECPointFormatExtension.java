package it.auties.leap.tls.extension.implementation;

import it.auties.leap.tls.TlsEngine;
import it.auties.leap.tls.ec.TlsECPointFormat;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.extension.TlsExtensionDecoder;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static it.auties.leap.tls.util.BufferUtils.*;

public record ECPointFormatExtension(
        List<Byte> ecPointFormats
) implements TlsExtension.Concrete {
    private static final ECPointFormatExtension ALL = new ECPointFormatExtension(List.of(
            TlsECPointFormat.uncompressed().id(),
            TlsECPointFormat.ansix962CompressedChar2().id(),
            TlsECPointFormat.ansix962CompressedPrime().id())
    );

    private static final TlsExtensionDecoder DECODER = new TlsExtensionDecoder() {
        @Override
        public Optional<? extends Concrete> decode(ByteBuffer buffer, int type, TlsEngine.Mode mode) {
            var ecPointFormatsSize = readLittleEndianInt8(buffer);
            var ecPointFormats = new ArrayList<Byte>();
            for(var i = 0; i < ecPointFormatsSize; i++) {
                var ecPointFormatId = readLittleEndianInt8(buffer);
                ecPointFormats.add(ecPointFormatId);
            }
            var extension = new ECPointFormatExtension(ecPointFormats);
            return Optional.of(extension);
        }

        @Override
        public Class<? extends Concrete> toConcreteType(TlsEngine.Mode mode) {
            return ECPointFormatExtension.class;
        }
    };

    public static ECPointFormatExtension of(List<TlsECPointFormat> formats) {
        return new ECPointFormatExtension(formats.stream()
                .map(TlsECPointFormat::id)
                .toList());
    }

    public static TlsExtension all() {
        return ALL;
    }

    @Override
    public void serializeExtensionPayload(ByteBuffer buffer) {
        writeLittleEndianInt8(buffer, ecPointFormats.size());
        for (var ecPointFormat : ecPointFormats) {
            writeLittleEndianInt8(buffer, ecPointFormat);
        }
    }

    @Override
    public int extensionPayloadLength() {
        return INT8_LENGTH + INT8_LENGTH * ecPointFormats.size();
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
    public TlsExtensionDecoder decoder() {
        return DECODER;
    }
}
