package it.auties.leap.tls.extension.concrete;

import it.auties.leap.tls.config.TlsEcPointFormat;
import it.auties.leap.tls.config.TlsIdentifiableUnion;
import it.auties.leap.tls.config.TlsVersion;
import it.auties.leap.tls.extension.TlsExtension;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static it.auties.leap.tls.BufferHelper.*;

public final class ECPointFormatsExtension extends TlsExtension.Concrete {
    public static final ECPointFormatsExtension ALL = new ECPointFormatsExtension(List.of(
            TlsIdentifiableUnion.of(TlsEcPointFormat.uncompressed()),
            TlsIdentifiableUnion.of(TlsEcPointFormat.ansix962CompressedPrime()),
            TlsIdentifiableUnion.of(TlsEcPointFormat.ansix962CompressedChar2()))
    );
    public static final int EXTENSION_TYPE = 0x000B;

    private final List<? extends TlsIdentifiableUnion<TlsEcPointFormat, Byte>> ecPointFormats;
    public ECPointFormatsExtension(List<? extends TlsIdentifiableUnion<TlsEcPointFormat, Byte>> ecPointFormats) {
        this.ecPointFormats = ecPointFormats;
    }


    public static Optional<ECPointFormatsExtension> of(TlsVersion version, ByteBuffer buffer, int extensionLength) {
        var ecPointFormatsSize = readLittleEndianInt8(buffer);
        var ecPointFormats = new ArrayList<TlsIdentifiableUnion<TlsEcPointFormat, Byte>>();
        for(var i = 0; i < ecPointFormatsSize; i++) {
            var ecPointFormatId = readLittleEndianInt8(buffer);
            ecPointFormats.add(TlsIdentifiableUnion.of(ecPointFormatId));
        }
        var extension = new ECPointFormatsExtension(ecPointFormats);
        return Optional.of(extension);
    }

    @Override
    protected void serializeExtensionPayload(ByteBuffer buffer) {
        writeLittleEndianInt8(buffer, ecPointFormats.size());
        for(var ecPointFormat : ecPointFormats) {
            writeLittleEndianInt8(buffer, ecPointFormat.id());
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
