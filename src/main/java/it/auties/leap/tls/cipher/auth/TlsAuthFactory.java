package it.auties.leap.tls.cipher.auth;

import it.auties.leap.tls.cipher.auth.implementation.*;

public interface TlsAuthFactory {
    static TlsAuthFactory contextual() {
        return ContextualAuth.factory();
    }

    static TlsAuthFactory anonymous() {
        return AnonymousAuth.factory();
    }

    static TlsAuthFactory dss() {
        return DSSAuth.factory();
    }

    static TlsAuthFactory eccpwd() {
        return ECCPWDAuth.factory();
    }

    static TlsAuthFactory ecdsa() {
        return ECDSAAuth.factory();
    }

    static TlsAuthFactory gostr256() {
        return GOSTR256Auth.factory();
    }

    static TlsAuthFactory krb5() {
        return KRB5Auth.factory();
    }

    static TlsAuthFactory psk() {
        return PSKAuth.factory();
    }

    static TlsAuthFactory rsa() {
        return RSAAuth.factory();
    }

    static TlsAuthFactory sha1() {
        return SHA1Auth.factory();
    }

    static TlsAuthFactory sha256() {
        return SHA256Auth.factory();
    }

    static TlsAuthFactory sha384() {
        return SHA384Auth.factory();
    }

    static TlsAuthFactory shaDss() {
        return SHADSSAuth.factory();
    }

    static TlsAuthFactory shaRsa() {
        return SHARSAAuth.factory();
    }

    static TlsAuthFactory hmacSha1() {
        return null;
    }

    TlsAuth newAuth();
    boolean isAnonymous();
}
