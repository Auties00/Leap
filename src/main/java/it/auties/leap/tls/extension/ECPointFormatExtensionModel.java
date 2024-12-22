package it.auties.leap.tls.extension;

import it.auties.leap.tls.config.TlsEcPointFormat;
import it.auties.leap.tls.config.TlsMode;
import it.auties.leap.tls.config.TlsVersion;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static it.auties.leap.tls.util.BufferHelper.*;

final class ECPointFormatExtensionModel implements TlsExtension.Model {
    @Override
    public Optional<? extends Implementation> newInstance(Context context) {
        return Optional.empty();
    }

    @Override
    public Optional<? extends Implementation> decode(ByteBuffer buffer, int type, TlsMode mode) {
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
    public Class<? extends Implementation> toConcreteType(TlsMode mode) {
        return ECPointFormatExtension.class;
    }

    @Override
    public Dependencies dependencies() {
        return Dependencies.none();
    }

    @Override
    public int extensionType() {
        return TlsExtensions.EC_POINT_FORMATS_TYPE;
    }

    @Override
    public List<TlsVersion> versions() {
        return TlsExtensions.EC_POINT_FORMATS_VERSIONS;
    }
}
