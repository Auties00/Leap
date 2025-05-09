package it.auties.leap.tls.ciphersuite.auth;

import it.auties.leap.tls.certificate.TlsCertificate;
import it.auties.leap.tls.ciphersuite.auth.implementation.*;
import it.auties.leap.tls.context.TlsContext;

import java.util.List;

public interface TlsAuth {
    static TlsAuth anonymous() {
        return AnonymousAuth.instance();
    }

    static TlsAuth dss() {
        return DSSAuth.instance();
    }

    static TlsAuth eccpwd() {
        return ECCPWDAuth.instance();
    }

    static TlsAuth ecdsa() {
        return ECDSAAuth.instance();
    }

    static TlsAuth gostr256() {
        return GOSTR256Auth.instance();
    }

    static TlsAuth krb5() {
        return KRB5Auth.instance();
    }

    static TlsAuth psk() {
        return PSKAuth.instance();
    }

    static TlsAuth rsa() {
        return RSAAuth.instance();
    }

    static TlsAuth sha1() {
        return SHA1Auth.instance();
    }

    static TlsAuth sha256() {
        return SHA256Auth.instance();
    }

    static TlsAuth sha384() {
        return SHA384Auth.instance();
    }

    static TlsAuth shaDss() {
        return SHADSSAuth.instance();
    }

    static TlsAuth shaRsa() {
        return SHARSAAuth.instance();
    }

    static TlsAuth hmacSha1() {
        return HMACSHA1Auth.instance();
    }

    
    TlsCertificate validate(TlsContext context, List<TlsCertificate> certificates, List<TlsCertificate> trustAnchors);
}
