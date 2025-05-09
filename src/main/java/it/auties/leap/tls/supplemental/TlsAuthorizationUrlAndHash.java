package it.auties.leap.tls.supplemental;

import java.nio.ByteBuffer;
import java.util.Objects;

import static it.auties.leap.tls.util.BufferUtils.*;

public final class TlsAuthorizationUrlAndHash {
    private final byte[] url;
    private final TlsAuthorizationHash hash;

    private TlsAuthorizationUrlAndHash(byte[] url, TlsAuthorizationHash hash) {
        this.url = url;
        this.hash = hash;
    }

    public static TlsAuthorizationUrlAndHash of(ByteBuffer buffer) {
        var url = readBytesBigEndian16(buffer);
        var hash = TlsAuthorizationHash.of(buffer)
                .orElseThrow(() -> new IllegalArgumentException("Invalid TLS hash"));
        return new TlsAuthorizationUrlAndHash(url, hash);
    }

    public static TlsAuthorizationUrlAndHash of(byte[] url, TlsAuthorizationHash hash) {
        Objects.requireNonNull(url, "url must not be null");
        Objects.requireNonNull(hash, "hash must not be null");
        return new TlsAuthorizationUrlAndHash(url, hash);
    }

    public byte[] url() {
        return url;
    }

    public TlsAuthorizationHash hash() {
        return hash;
    }

    public void serialize(ByteBuffer buffer) {
        writeBytesBigEndian16(buffer, url);
        hash.serialize(buffer);
    }

    public int length() {
        return INT16_LENGTH + url.length
                + hash.length();
    }
}
