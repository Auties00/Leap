package it.auties.leap.tls.certificate;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
import it.auties.leap.tls.hash.TlsHashFactory;

import java.nio.ByteBuffer;
import java.util.Objects;

import static it.auties.leap.tls.util.BufferUtils.*;

public final class TlsCertificateUrlAndHash {
    private static final int SHA1_HASH_LENGTH = TlsHashFactory.sha1()
            .length();

    private final byte[] url;
    private final int padding;
    private final byte[] hash;

    private TlsCertificateUrlAndHash(byte[] url, int padding, byte[] hash) {
        this.url = url;
        this.padding = padding;
        this.hash = hash;
    }

    public static TlsCertificateUrlAndHash of(byte[] url, int padding, byte[] hash) {
        Objects.requireNonNull(url, "Url cannot be null");
        if (padding < 0) {
            throw new IllegalArgumentException("Padding shouldn't be negative");
        }
        Objects.requireNonNull(hash, "Hash cannot be null");
        if (hash.length != SHA1_HASH_LENGTH) {
            throw new IllegalArgumentException("Hash length mismatch: expected %s, got %s".formatted(SHA1_HASH_LENGTH, hash.length));
        }
        return new TlsCertificateUrlAndHash(url, padding, hash);
    }

    public static TlsCertificateUrlAndHash of(ByteBuffer buffer) {
        var url = readBytesBigEndian16(buffer);
        var padding = readBigEndianInt8(buffer);
        if(padding < 0) {
            throw new TlsAlert("Padding shouldn't be negative", TlsAlertLevel.FATAL, TlsAlertType.ILLEGAL_PARAMETER);
        }
        var hash = readBytes(buffer, SHA1_HASH_LENGTH);
        return new TlsCertificateUrlAndHash(url, padding, hash);
    }

    public byte[] url() {
        return url;
    }

    public int padding() {
        return padding;
    }

    public byte[] hash() {
        return hash;
    }

    public void serialize(ByteBuffer buffer) {
        writeBytesBigEndian16(buffer, url);
        writeBigEndianInt8(buffer, padding);
        writeBytes(buffer, hash);
    }

    public int length() {
        return INT16_LENGTH + url.length
                + INT8_LENGTH
                + SHA1_HASH_LENGTH;
    }
}
