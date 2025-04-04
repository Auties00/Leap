package it.auties.leap.tls.message;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;

import static it.auties.leap.tls.util.BufferUtils.*;

public record TlsMessageMetadata(
        TlsMessageContentType contentType,
        TlsVersion version,
        int length,
        TlsSource source
) {
    public TlsMessageMetadata {
        if(contentType == null) {
            throw new TlsAlert("Invalid content type");
        }

        if(version == null) {
            throw new TlsAlert("Invalid version");
        }

        if(source == null) {
            throw new TlsAlert("Invalid source");
        }
    }

    private static final int LENGTH = INT8_LENGTH + INT16_LENGTH + INT16_LENGTH;

    public static TlsMessageMetadata of(ByteBuffer buffer, TlsSource source) {
        var contentTypeId = readBigEndianInt8(buffer);
        var contentType = TlsMessageContentType.of(contentTypeId)
                .orElseThrow(() -> new IllegalArgumentException("Cannot decode TLS message, unknown content type: " + contentTypeId));
        var protocolVersionMajor = readBigEndianInt8(buffer);
        var protocolVersionMinor = readBigEndianInt8(buffer);
        var protocolVersion = TlsVersion.of(protocolVersionMajor, protocolVersionMinor)
                .orElseThrow(() -> new IllegalArgumentException("Cannot decode TLS message, unknown protocol version: major %s, minor %s".formatted(protocolVersionMajor, protocolVersionMinor)));
        var length = readBigEndianInt16(buffer);
        return new TlsMessageMetadata(contentType, protocolVersion, length, source);
    }

    public static int structureLength() {
        return LENGTH;
    }

    public TlsMessageMetadata withLength(int length) {
        if(this.length == length) {
            return this;
        }

        return new TlsMessageMetadata(contentType, version, length, source);
    }
}
