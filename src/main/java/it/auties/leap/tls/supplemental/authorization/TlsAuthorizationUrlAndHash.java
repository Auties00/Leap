package it.auties.leap.tls.supplemental.authorization;

import it.auties.leap.tls.property.TlsSerializableProperty;

import java.nio.ByteBuffer;

import static it.auties.leap.tls.util.BufferUtils.*;

public final class TlsAuthorizationUrlAndHash implements TlsSerializableProperty {
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

    public static TlsAuthorizationUrlAndHash newUrlAndHash(byte[] url, TlsAuthorizationHash hash) {
        if (url == null) {
            throw new NullPointerException("url");
        }

        if(hash == null) {
            throw new NullPointerException("hash");
        }

        return new TlsAuthorizationUrlAndHash(url, hash);
    }

    public byte[] url() {
        return url;
    }

    public TlsAuthorizationHash hash() {
        return hash;
    }

    @Override
    public void serialize(ByteBuffer buffer) {
        writeBytesBigEndian16(buffer, url);
        hash.serialize(buffer);
    }

    @Override
    public int length() {
        return INT16_LENGTH + url.length
                + hash.length();
    }
}
