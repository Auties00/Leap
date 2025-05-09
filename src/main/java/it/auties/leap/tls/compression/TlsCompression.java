package it.auties.leap.tls.compression;

import it.auties.leap.tls.version.TlsVersion;

import java.util.Collections;
import java.util.List;
import java.util.Objects;

public final class TlsCompression {
    private static final List<TlsVersion> ANY_VERSION = List.of(TlsVersion.values());

    private static final TlsCompression NONE = new TlsCompression((byte) 0, ANY_VERSION, Type.NONE, TlsCompressor.none());
    private static final TlsCompression DEFLATE = new TlsCompression((byte) 1, List.of(TlsVersion.values()), Type.DEFLATE, TlsCompressor.deflate());
    private static final List<TlsCompression> VALUES = List.of(NONE, DEFLATE);
    private static final List<TlsCompression> RECOMMENDED = List.of(NONE);

    private final byte id;
    private final List<TlsVersion> versions;
    private final Type type;
    private final TlsCompressor compressor;

    private TlsCompression(byte id, List<TlsVersion> versions, Type type, TlsCompressor compressor) {
        this.id = id;
        this.versions = versions;
        this.type = type;
        this.compressor = compressor;
    }

    public static TlsCompression none() {
        return NONE;
    }

    public static TlsCompression deflate() {
        return DEFLATE;
    }

    public static TlsCompression reservedForPrivateUse(byte id) {
        return reservedForPrivateUse(id, ANY_VERSION);
    }

    public static TlsCompression reservedForPrivateUse(byte id, List<TlsVersion> versions) {
        return reservedForPrivateUse(id, versions, null);
    }

    public static TlsCompression reservedForPrivateUse(byte id, List<TlsVersion> versions, TlsCompressor compressor) {
        if (id < -32 || id > -1) {
            throw new IllegalArgumentException("Only values from 224-255 (decimal) inclusive are reserved for Private Use");
        }

        if(versions == null || versions.isEmpty()) {
            throw new IllegalArgumentException("Invalid versions");
        }

        var safeCompressor = Objects.requireNonNullElse(compressor, TlsCompressor.unsupported());
        return new TlsCompression(id, versions, Type.RESERVED_FOR_PRIVATE_USE, safeCompressor);
    }

    public static List<TlsCompression> values() {
        return VALUES;
    }

    public static List<TlsCompression> recommended() {
        return RECOMMENDED;
    }

    public byte id() {
        return id;
    }

    public List<TlsVersion> versions() {
        return Collections.unmodifiableList(versions);
    }

    public Type type() {
        return type;
    }

    public TlsCompressor compressor() {
        return compressor;
    }

    public enum Type {
        NONE,
        DEFLATE,
        RESERVED_FOR_PRIVATE_USE
    }
}
