package it.auties.leap.tls.message;

import it.auties.leap.tls.TlsSource;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;

import static it.auties.leap.tls.util.BufferUtils.*;

public record TlsMessageMetadata(TlsMessageContentType contentType, TlsVersion version, int messageLength) {
    private static final int LENGTH = INT8_LENGTH + INT16_LENGTH + INT16_LENGTH;

    public static TlsMessageMetadata of(ByteBuffer buffer) {
        var contentTypeId = readBigEndianInt8(buffer);
        var contentType = TlsMessageContentType.of(contentTypeId)
                .orElseThrow(() -> new IllegalArgumentException("Cannot decode TLS message, unknown content type: " + contentTypeId));
        var protocolVersionMajor = readBigEndianInt8(buffer);
        var protocolVersionMinor = readBigEndianInt8(buffer);
        var protocolVersion = TlsVersion.of(protocolVersionMajor, protocolVersionMinor)
                .orElseThrow(() -> new IllegalArgumentException("Cannot decode TLS message, unknown protocol version: major %s, minor %s".formatted(protocolVersionMajor, protocolVersionMinor)));
        var messageLength = readBigEndianInt16(buffer);
        return new TlsMessageMetadata(contentType, protocolVersion, messageLength);
    }

    public TlsSource source() {
        return TlsSource.REMOTE;
    }

    public static int length() {
        return LENGTH;
    }

    public TlsMessageMetadata withMessageLength(int messageLength) {
        return new TlsMessageMetadata(contentType, version, messageLength);
    }
}
