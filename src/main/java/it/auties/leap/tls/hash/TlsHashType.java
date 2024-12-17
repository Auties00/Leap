package it.auties.leap.tls.hash;

public interface TlsHashType {
    static TlsHashType none() {
        return NULLDigest.INSTANCE;
    }

    static TlsHashType md5() {
        return new MD5Digest();
    }

    static TlsHashType sha1() {
        return new SHA1Digest();
    }

    static TlsHashType sha256() {
        return new SHA256Digest();
    }

    static TlsHashType sha384() {
        return new SHA384Digest();
    }

    static TlsHashType sm3() {
        return new SM3Digest();
    }

    static TlsHashType gostr341112_256() {
        return new GOSTR256Digest();
    }

    int length();
    int blockLength();
    TlsHash newHash();
}
