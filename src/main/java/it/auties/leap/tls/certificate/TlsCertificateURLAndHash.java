package it.auties.leap.tls.certificate;

import it.auties.leap.tls.hash.TlsHashFactory;
import it.auties.leap.tls.property.TlsSerializableProperty;

import java.nio.ByteBuffer;

import static it.auties.leap.tls.util.BufferUtils.*;

public final class TlsCertificateURLAndHash implements TlsSerializableProperty {
    private static final int SHA1_HASH_LENGTH = TlsHashFactory.sha1()
            .length();

    private final byte[] url;
    private final int padding;
    private final byte[] hash;

    private TlsCertificateURLAndHash(byte[] url, int padding, byte[] hash) {
        this.url = url;
        this.padding = padding;
        this.hash = hash;
    }

    public static TlsCertificateURLAndHash newUrlAndHash(byte[] url, int padding, byte[] hash) {
        if (url == null) {
            throw new NullPointerException("url");
        }

        if (padding < 0) {
            throw new IllegalArgumentException("padding");
        }

        if(hash == null || hash.length != SHA1_HASH_LENGTH) {
            throw new NullPointerException("hash");
        }

        return new TlsCertificateURLAndHash(url, padding, hash);
    }

    public static TlsCertificateURLAndHash of(ByteBuffer buffer) {
        var url = readBytesBigEndian16(buffer);
        var padding = readBigEndianInt8(buffer);
        var hash = readBytes(buffer, SHA1_HASH_LENGTH);
        return new TlsCertificateURLAndHash(url, padding, hash);
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

    @Override
    public void serialize(ByteBuffer buffer) {
        writeBytesBigEndian16(buffer, url);
        writeBigEndianInt8(buffer, padding);
        writeBytes(buffer, hash);
    }

    @Override
    public int length() {
        return INT16_LENGTH + url.length
                + INT8_LENGTH
                + SHA1_HASH_LENGTH;
    }
}
