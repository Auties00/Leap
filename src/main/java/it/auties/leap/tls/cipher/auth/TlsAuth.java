package it.auties.leap.tls.cipher.auth;

public interface TlsAuth {
    static TlsAuth none() {
        return null;
    }

    static TlsAuth anonymous() {
        return null;
    }

    static TlsAuth dss() {
        return null;
    }

    static TlsAuth eccPwd() {
        return null;
    }

    static TlsAuth ecDsa() {
        return null;
    }

    static TlsAuth gostr341012() {
        return null;
    }

    static TlsAuth krb5() {
        return null;
    }

    static TlsAuth psk() {
        return null;
    }

    static TlsAuth rsa() {
        return null;
    }

    static TlsAuth sha() {
        return null;
    }

    static TlsAuth sha256() {
        return null;
    }

    static TlsAuth sha384() {
        return null;
    }

    static TlsAuth shaDss() {
        return null;
    }

    static TlsAuth shaRsa() {
        return null;
    }
}
