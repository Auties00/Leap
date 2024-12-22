package it.auties.leap.tls.config;

import java.util.List;
import java.util.Objects;

public final class TlsVersionId {
    private static final TlsVersionId GREASE_0A = new TlsVersionId(0x0A0A);
    private static final TlsVersionId GREASE_1A = new TlsVersionId(0x1A1A);
    private static final TlsVersionId GREASE_2A = new TlsVersionId(0x2A2A);
    private static final TlsVersionId GREASE_3A = new TlsVersionId(0x3A3A);
    private static final TlsVersionId GREASE_4A = new TlsVersionId(0x4A4A);
    private static final TlsVersionId GREASE_5A = new TlsVersionId(0x5A5A);
    private static final TlsVersionId GREASE_6A = new TlsVersionId(0x6A6A);
    private static final TlsVersionId GREASE_7A = new TlsVersionId(0x7A7A);
    private static final TlsVersionId GREASE_8A = new TlsVersionId(0x8A8A);
    private static final TlsVersionId GREASE_9A = new TlsVersionId(0x9A9A);
    private static final TlsVersionId GREASE_AA = new TlsVersionId(0xAAAA);
    private static final TlsVersionId GREASE_BA = new TlsVersionId(0xBABA);
    private static final TlsVersionId GREASE_CA = new TlsVersionId(0xCACA);
    private static final TlsVersionId GREASE_DA = new TlsVersionId(0xDADA);
    private static final TlsVersionId GREASE_EA = new TlsVersionId(0xEAEA);
    private static final TlsVersionId GREASE_FA = new TlsVersionId(0xFAFA);
    private static final List<TlsVersionId> GREASE = List.of(GREASE_0A, GREASE_1A, GREASE_2A, GREASE_3A, GREASE_4A, GREASE_5A, GREASE_6A, GREASE_7A, GREASE_8A, GREASE_9A, GREASE_AA, GREASE_BA, GREASE_CA, GREASE_DA, GREASE_EA, GREASE_FA);

    public static TlsVersionId grease0A() {
        return GREASE_0A;
    }

    public static TlsVersionId grease1A() {
        return GREASE_1A;
    }

    public static TlsVersionId grease2A() {
        return GREASE_2A;
    }

    public static TlsVersionId grease3A() {
        return GREASE_3A;
    }

    public static TlsVersionId grease4A() {
        return GREASE_4A;
    }

    public static TlsVersionId grease5A() {
        return GREASE_5A;
    }

    public static TlsVersionId grease6A() {
        return GREASE_6A;
    }

    public static TlsVersionId grease7A() {
        return GREASE_7A;
    }

    public static TlsVersionId grease8A() {
        return GREASE_8A;
    }

    public static TlsVersionId grease9A() {
        return GREASE_9A;
    }

    public static TlsVersionId greaseAA() {
        return GREASE_AA;
    }

    public static TlsVersionId greaseBA() {
        return GREASE_BA;
    }

    public static TlsVersionId greaseCA() {
        return GREASE_CA;
    }

    public static TlsVersionId greaseDA() {
        return GREASE_DA;
    }

    public static TlsVersionId greaseEA() {
        return GREASE_EA;
    }

    public static TlsVersionId greaseFA() {
        return GREASE_FA;
    }

    public static List<TlsVersionId> grease() {
        return GREASE;
    }

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
