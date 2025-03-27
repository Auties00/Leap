package it.auties.leap.tls.message;

import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;
import java.util.Objects;

import static it.auties.leap.tls.util.BufferUtils.*;

public final class TlsMessageMetadata {
    private static final int LENGTH = INT8_LENGTH + INT16_LENGTH + INT16_LENGTH;

    private final TlsMessageContentType contentType;
    private final TlsVersion version;
    private final int length;
    private final TlsSource source;

    private TlsMessageMetadata(TlsMessageContentType contentType, TlsVersion version, int length, TlsSource source) {
        this.contentType = contentType;
        this.version = version;
        this.length = length;
        this.source = source;
    }

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

    public TlsMessageContentType contentType() {
        return contentType;
    }

    public TlsVersion version() {
        return version;
    }

    public int messageLength() {
        return length;
    }

    public TlsSource source() {
        return source;
    }

    public TlsMessageMetadata withLength(int length) {
        return new TlsMessageMetadata(contentType, version, length, source);
    }

    public TlsMessageMetadata withSource(TlsSource source) {
        return new TlsMessageMetadata(contentType, version, length, source);
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof TlsMessageMetadata that
                && length == that.length
                && contentType == that.contentType
                && version == that.version
                && source == that.source;
    }

    @Override
    public int hashCode() {
        return Objects.hash(contentType, version, length, source);
    }

    @Override
    public String toString() {
        return "TlsMessageMetadata{" +
                "contentType=" + contentType +
                ", version=" + version +
                ", length=" + length +
                ", source=" + source +
                '}';
    }
}
