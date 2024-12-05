package it.auties.leap.tls.extension.concrete;

import it.auties.leap.tls.TlsEcPointFormat;
import it.auties.leap.tls.TlsVersion;
import it.auties.leap.tls.extension.TlsConcreteExtension;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static it.auties.leap.tls.TlsRecord.*;

public final class ECPointFormatsExtension extends TlsConcreteExtension {
    public static final ECPointFormatsExtension ALL = new ECPointFormatsExtension(Arrays.asList(TlsEcPointFormat.values()));
    public static final int EXTENSION_TYPE = 0x000B;

    private final List<TlsEcPointFormat> ecPointFormats;
    public ECPointFormatsExtension(List<TlsEcPointFormat> ecPointFormats) {
        this.ecPointFormats = ecPointFormats;
    }

    public static Optional<ECPointFormatsExtension> of(TlsVersion version, ByteBuffer buffer, int extensionLength) {
        var ecPointFormatsSize = readInt8(buffer);
        var ecPointFormats = new ArrayList<TlsEcPointFormat>();
        for(var i = 0; i < ecPointFormatsSize; i++) {
            var ecPointFormatId = readInt8(buffer);
            var ecPointFormat = TlsEcPointFormat.of(ecPointFormatId)
                    .orElseThrow(() -> new IllegalArgumentException("Unknown ec point format: " + ecPointFormatId));
            ecPointFormats.add(ecPointFormat);
        }
        var extension = new ECPointFormatsExtension(ecPointFormats);
        return Optional.of(extension);
    }

    @Override
    protected void serializeExtensionPayload(ByteBuffer buffer) {
        writeInt8(buffer, ecPointFormats.size());
        for(var ecPointFormat : ecPointFormats) {
            writeInt8(buffer, ecPointFormat.id());
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
