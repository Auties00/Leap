package it.auties.leap.tls;

import java.security.SecureRandom;
import java.util.Objects;

// Implementing a new version is not a supported use case: this is why this class is implemented as final
public final class TlsVersionId {
    public static final TlsVersionId[] GREASE = new TlsVersionId[]{
            new TlsVersionId(0x0A0A),
            new TlsVersionId(0x1A1A),
            new TlsVersionId(0x2A2A),
            new TlsVersionId(0x3A3A),
            new TlsVersionId(0x4A4A),
            new TlsVersionId(0x5A5A),
            new TlsVersionId(0x6A6A),
            new TlsVersionId(0x7A7A),
            new TlsVersionId(0x8A8A),
            new TlsVersionId(0x9A9A),
            new TlsVersionId(0xAAAA),
            new TlsVersionId(0xBABA),
            new TlsVersionId(0xCACA),
            new TlsVersionId(0xDADA),
            new TlsVersionId(0xEAEA),
            new TlsVersionId(0xFAFA)
    };

    public static TlsVersionId grease0A() {
        return TlsVersionId.GREASE[0];
    }

    public static TlsVersionId grease1A() {
        return TlsVersionId.GREASE[1];
    }

    public static TlsVersionId grease2A() {
        return TlsVersionId.GREASE[2];
    }

    public static TlsVersionId grease3A() {
        return TlsVersionId.GREASE[3];
    }

    public static TlsVersionId grease4A() {
        return TlsVersionId.GREASE[4];
    }

    public static TlsVersionId grease5A() {
        return TlsVersionId.GREASE[5];
    }

    public static TlsVersionId grease6A() {
        return TlsVersionId.GREASE[6];
    }

    public static TlsVersionId grease7A() {
        return TlsVersionId.GREASE[7];
    }

    public static TlsVersionId grease8A() {
        return TlsVersionId.GREASE[8];
    }

    public static TlsVersionId grease9A() {
        return TlsVersionId.GREASE[9];
    }

    public static TlsVersionId greaseAA() {
        return TlsVersionId.GREASE[10];
    }

    public static TlsVersionId greaseBA() {
        return TlsVersionId.GREASE[11];
    }

    public static TlsVersionId greaseCA() {
        return TlsVersionId.GREASE[12];
    }

    public static TlsVersionId greaseDA() {
        return TlsVersionId.GREASE[13];
    }

    public static TlsVersionId greaseEA() {
        return TlsVersionId.GREASE[14];
    }

    public static TlsVersionId greaseFA() {
        return TlsVersionId.GREASE[15];
    }

    public static TlsVersionId grease() {
        var random = new SecureRandom();
        return TlsVersionId.GREASE[random.nextInt(0, TlsVersionId.GREASE.length)];
    }
    
    private final int value;
    private final byte major;
    private final byte minor;
    public TlsVersionId(int value) {
        this.value = value;
        this.major = getMajor(value);
        this.minor = getMinor(value);
    }

    public TlsVersionId(byte major, byte minor) {
        this.value = getId(major, minor);
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
