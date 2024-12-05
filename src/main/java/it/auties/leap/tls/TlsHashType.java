package it.auties.leap.tls;

public enum TlsHashType {
    NULL(0, 0),
    MD5(16, 64),
    SHA1(20, 64),
    SHA256(32, 64),
    SHA384(48, 128),
    SM3(32, 64),
    GOSTR341112_256(32, 64);

    private final int length;
    private final int blockLength;

    TlsHashType(int length, int blockLength) {
        this.length = length;
        this.blockLength = blockLength;
    }

    public int length() {
        return length;
    }

    public int blockLength() {
        return blockLength;
    }

    public TlsHmacType toHmac() {
        return switch (this) {
            case NULL -> TlsHmacType.NULL;
            case MD5 -> TlsHmacType.HMAC_MD5;
            case SHA1 -> TlsHmacType.HMAC_SHA1;
            case SHA256 -> TlsHmacType.HMAC_SHA256;
            case SHA384 -> TlsHmacType.HMAC_SHA384;
            case SM3 -> TlsHmacType.HMAC_SM3;
            case GOSTR341112_256 -> TlsHmacType.HMAC_GOSTR341112_256;
        };
    }
}
