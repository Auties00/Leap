package it.auties.leap.tls.ec;

public final class TlsEcPointFormat {
    private static final TlsEcPointFormat UNCOMPRESSED = new TlsEcPointFormat((byte) 0);
    private static final TlsEcPointFormat ANSIX_962_COMPRESSED_PRIME = new TlsEcPointFormat((byte) 1);
    private static final TlsEcPointFormat ANSIX_962_COMPRESSED_CHAR_2 = new TlsEcPointFormat((byte) 2);

    private final byte id;

    private TlsEcPointFormat(byte id) {
        this.id = id;
    }

    public static TlsEcPointFormat uncompressed() {
        return UNCOMPRESSED;
    }

    public static TlsEcPointFormat ansix962CompressedPrime() {
        return ANSIX_962_COMPRESSED_PRIME;
    }

    public static TlsEcPointFormat ansix962CompressedChar2() {
        return ANSIX_962_COMPRESSED_CHAR_2;
    }

    static TlsEcPointFormat reservedForPrivateUse(byte id) {
        if (id < -8 || id > -1) {
            throw new IllegalArgumentException("Only values from 248-255 (decimal) inclusive are reserved for Private Use");
        }

        return new TlsEcPointFormat(id);
    }

    public byte id() {
        return id;
    }
}
