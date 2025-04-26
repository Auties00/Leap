package it.auties.leap.tls.message;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
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

    public static TlsMessageMetadata of(TlsMessageContentType contentType, TlsVersion version, int length, TlsSource source) {
        if (contentType == null) {
            throw new TlsAlert("Invalid content type", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
        }

        if (version == null) {
            throw new TlsAlert("Invalid version", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
        }

        if (source == null) {
            throw new TlsAlert("Invalid source", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
        }

        return new TlsMessageMetadata(contentType, version, length, source);
    }

    public static int structureLength() {
        return LENGTH;
    }

    public TlsMessageMetadata withLength(int length) {
        if (this.length == length) {
            return this;
        }

        return new TlsMessageMetadata(contentType, version, length, source);
    }

    public TlsMessageContentType contentType() {
        return contentType;
    }

    public TlsVersion version() {
        return version;
    }

    public int length() {
        return length;
    }

    public TlsSource source() {
        return source;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == this) return true;
        if (obj == null || obj.getClass() != this.getClass()) return false;
        var that = (TlsMessageMetadata) obj;
        return Objects.equals(this.contentType, that.contentType) &&
                Objects.equals(this.version, that.version) &&
                this.length == that.length &&
                Objects.equals(this.source, that.source);
    }

    @Override
    public int hashCode() {
        return Objects.hash(contentType, version, length, source);
    }

    @Override
    public String toString() {
        return "TlsMessageMetadata[" +
                "contentType=" + contentType + ", " +
                "version=" + version + ", " +
                "length=" + length + ", " +
                "source=" + source + ']';
    }

}
