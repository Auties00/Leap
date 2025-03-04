package it.auties.leap.tls.cipher.auth;

public interface TlsAuthFactory {
    static TlsAuthFactory any() {
        return () -> null;
    }

    static TlsAuthFactory anonymous() {
        return () -> null;
    }

    static TlsAuthFactory dss() {
        return () -> null;
    }

    static TlsAuthFactory eccpwd() {
        return () -> null;
    }

    static TlsAuthFactory ecdsa() {
        return () -> null;
    }

    static TlsAuthFactory gostr341012_256() {
        return () -> null;
    }

    static TlsAuthFactory krb5() {
        return () -> null;
    }

    static TlsAuthFactory psk() {
        return () -> null;
    }

    static TlsAuthFactory rsa() {
        return () -> null;
    }

    static TlsAuthFactory sha() {
        return () -> null;
    }

    static TlsAuthFactory sha256() {
        return () -> null;
    }

    static TlsAuthFactory sha384() {
        return () -> null;
    }

    static TlsAuthFactory shaDss() {
        return () -> null;
    }

    static TlsAuthFactory shaRsa() {
        return () -> null;
    }

    TlsAuth newAuth();
}
