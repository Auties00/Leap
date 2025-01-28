package it.auties.leap.tls.version;

import java.util.Objects;

public final class TlsVersionId {
    public static TlsVersionId of(int value) {
        return new TlsVersionId(value);
    }

    public static TlsVersionId of(byte major, byte minor) {
        return new TlsVersionId(major, minor);
    }

    private final int value;
    private final byte major;
    private final byte minor;
    TlsVersionId(int value) {
        this(value, getMajor(value), getMinor(value));
    }

    TlsVersionId(byte major, byte minor) {
        this(getId(major, minor), major, minor);
    }

    TlsVersionId(int value, byte major, byte minor) {
        this.value = value;
        this.major = major;
        this.minor = minor;
    }

    public static byte getMajor(int value) {
        return (byte) ((value >>> 8) & 0xFF);
    }

    public static byte getMinor(int value) {
        return (byte) (value & 0xFF);
    }

    public static int getId(byte major, byte minor) {
        return (major << 8) + minor;
    }

    public int value() {
        return value;
    }

    public byte major() {
        return major;
    }

    public byte minor() {
        return minor;
    }

    @Override
    public boolean equals(Object obj) {
        return obj == this || obj instanceof TlsVersionId that && this.value == that.value;
    }

    @Override
    public int hashCode() {
        return Objects.hash(major, minor);
    }

    @Override
    public String toString() {
        return "TlsVersionId[" +
                "major=" + major + ", " +
                "minor=" + minor + ']';
    }
}
