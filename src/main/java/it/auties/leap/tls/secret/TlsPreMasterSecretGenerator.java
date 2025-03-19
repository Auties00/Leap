package it.auties.leap.tls.secret;

import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.secret.implementation.*;

public interface TlsPreMasterSecretGenerator {
    byte[] generatePreMasterSecret(TlsContext context);

    static TlsPreMasterSecretGenerator dh() {
        return DhPreMasterSecretGenerator.instance();
    }

    static TlsPreMasterSecretGenerator eccpwd() {
        return EccPwdPreMasterSecretGenerator.instance();
    }

    static TlsPreMasterSecretGenerator ecdh() {
        return EcdhPreMasterSecretGenerator.instance();
    }

    static TlsPreMasterSecretGenerator gostr256() {
        return Gostr256PreMasterSecretGenerator.instance();
    }

    static TlsPreMasterSecretGenerator krb5() {
        return Krb5PreMasterSecretGenerator.instance();
    }

    static TlsPreMasterSecretGenerator contextual() {
        return NonePreMasterSecretGenerator.instance();
    }

    static TlsPreMasterSecretGenerator psk() {
        return PskPreMasterSecretGenerator.instance();
    }

    static TlsPreMasterSecretGenerator rsa() {
        return RsaPreMasterSecretGenerator.instance();
    }

    static TlsPreMasterSecretGenerator srp() {
        return SrpPreMasterSecretGenerator.instance();
    }
}
