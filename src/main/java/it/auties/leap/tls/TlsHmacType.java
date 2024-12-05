package it.auties.leap.tls;

public enum TlsHmacType {
    NULL(0, TlsHashType.NULL, 0),
    HMAC_MD5(16, TlsHashType.MD5, 9),
    HMAC_SHA1(20, TlsHashType.SHA1, 9),
    HMAC_SHA256(32, TlsHashType.SHA256, 9),
    HMAC_SHA384(48, TlsHashType.SHA384, 17),
    HMAC_GOSTR341112_256(32, TlsHashType.GOSTR341112_256, 9),
    HMAC_SM3(32, TlsHashType.SM3, 9);

    private final int length;
    private final TlsHashType underlyingHashType;
    private final int minimalPaddingLength;

    TlsHmacType(int length, TlsHashType underlyingHashType, int minimalPaddingLength) {
        this.length = length;
        this.underlyingHashType = underlyingHashType;
        this.minimalPaddingLength = minimalPaddingLength;
    }

    public int length() {
        return length;
    }

    public TlsHashType toHash() {
        return underlyingHashType;
    }

    public int minimalPaddingLength() {
        return minimalPaddingLength;
    }
}
