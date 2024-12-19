package it.auties.leap.tls.extension.concrete;

import it.auties.leap.tls.config.TlsEcPointFormat;
import it.auties.leap.tls.config.TlsVersion;
import it.auties.leap.tls.extension.TlsExtension;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static it.auties.leap.tls.BufferHelper.*;

public record ECPointFormatsExtension(List<Byte> ecPointFormats) implements TlsExtension.Concrete {
    public static final ECPointFormatsExtension ALL = new ECPointFormatsExtension(List.of(
            TlsEcPointFormat.uncompressed().id(),
            TlsEcPointFormat.ansix962CompressedPrime().id(),
            TlsEcPointFormat.ansix962CompressedChar2().id()
    ));
    public static final int EXTENSION_TYPE = 0x000B;

    public static Optional<ECPointFormatsExtension> of(TlsVersion version, ByteBuffer buffer, int extensionLength) {
        var ecPointFormatsSize = readLittleEndianInt8(buffer);
        var ecPointFormats = new ArrayList<Byte>();
        for(var i = 0; i < ecPointFormatsSize; i++) {
            var ecPointFormatId = readLittleEndianInt8(buffer);
            ecPointFormats.add(ecPointFormatId);
        }
        var extension = new ECPointFormatsExtension(ecPointFormats);
        return Optional.of(extension);
    }

    @Override
    public void serializeExtensionPayload(ByteBuffer buffer) {
        writeLittleEndianInt8(buffer, ecPointFormats.size());
        for(var ecPointFormat : ecPointFormats) {
            writeLittleEndianInt8(buffer, ecPointFormat);
        }
    }

    @Override
    public int extensionPayloadLength() {
        return INT8_LENGTH + ecPointFormats.size();
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
