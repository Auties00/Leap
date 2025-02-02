package it.auties.leap.tls.hash;

import it.auties.leap.tls.hash.implementation.*;

public interface TlsHashFactory {
    static TlsHashFactory none() {
        return NoneHash.factory();
    }

    static TlsHashFactory md5() {
        return MD5Hash.factory();
    }

    static TlsHashFactory sha1() {
        return SHA1Hash.factory();
    }

    static TlsHashFactory sha256() {
        return SHA256Hash.factory();
    }

    static TlsHashFactory sha384() {
        return SHA384Hash.factory();
    }

    static TlsHashFactory sm3() {
        return SM3Hash.factory();
    }

    static TlsHashFactory gostr341112_256() {
        return GOSTR341112_256_Hash.factory();
    }
    
    TlsHash newHash();

    int length();
}
