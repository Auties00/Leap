package it.auties.leap.tls.message;

import it.auties.leap.tls.TlsSource;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;
import java.util.Objects;

import static it.auties.leap.tls.util.BufferUtils.*;

public final class TlsMessageMetadata {
    private static final int LENGTH = INT8_LENGTH + INT16_LENGTH + INT16_LENGTH;

    private final TlsMessageContentType contentType;
    private final TlsVersion version;
    private final int messageLength;

    private TlsMessageMetadata(TlsMessageContentType contentType, TlsVersion version, int messageLength) {
        this.contentType = contentType;
        this.version = version;
        this.messageLength = messageLength;
    }

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

    public TlsMessageContentType contentType() {
        return contentType;
    }

    public TlsVersion version() {
        return version;
    }

    public int messageLength() {
        return messageLength;
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof TlsMessageMetadata that
                && messageLength == that.messageLength
                && contentType == that.contentType
                && version == that.version;
    }

    @Override
    public int hashCode() {
        return Objects.hash(contentType, version, messageLength);
    }

    @Override
    public String toString() {
        return "TlsMessageMetadata[" +
                "contentType=" + contentType + ", " +
                "version=" + version + ", " +
                "messageLength=" + messageLength + ']';
    }
}
