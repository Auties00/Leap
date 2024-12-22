package it.auties.leap.tls.extension;

import it.auties.leap.tls.config.TlsVersion;

import java.nio.ByteBuffer;
import java.util.List;

import static it.auties.leap.tls.util.BufferHelper.INT8_LENGTH;
import static it.auties.leap.tls.util.BufferHelper.writeLittleEndianInt8;

public final class ECPointFormatExtension implements TlsExtension.Implementation {
    private final List<Byte> ecPointFormats;
    ECPointFormatExtension(List<Byte> ecPointFormats) {
        this.ecPointFormats = ecPointFormats;
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
        return INT8_LENGTH + ecPointFormats.size();
    }

    @Override
    public int extensionType() {
        return TlsExtensions.EC_POINT_FORMATS_TYPE;
    }

    @Override
    public List<TlsVersion> versions() {
        return TlsExtensions.EC_POINT_FORMATS_VERSIONS;
    }

    public List<Byte> ecPointFormats() {
        return ecPointFormats;
    }
}
