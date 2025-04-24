package it.auties.leap.tls.secret;

import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.secret.implementation.*;

public interface TlsPreMasterSecretGenerator {
    TlsSecret generatePreMasterSecret(TlsContext context);

    static TlsPreMasterSecretGenerator dh() {
        return SupportedGroupPreMasterSecretGenerator.instance();
    }

    static TlsPreMasterSecretGenerator eccpwd() {
        return ECCPWDPreMasterSecretGenerator.instance();
    }

    static TlsPreMasterSecretGenerator ecdh() {
        return SupportedGroupPreMasterSecretGenerator.instance();
    }

    static TlsPreMasterSecretGenerator gostr256() {
        return GOSTR256PreMasterSecretGenerator.instance();
    }

    static TlsPreMasterSecretGenerator krb5() {
        return KRB5PreMasterSecretGenerator.instance();
    }

    static TlsPreMasterSecretGenerator contextual() {
        return SupportedGroupPreMasterSecretGenerator.instance();
    }

    static TlsPreMasterSecretGenerator psk() {
        return PSKPreMasterSecretGenerator.instance();
    }

    static TlsPreMasterSecretGenerator rsa() {
        return RSAPreMasterSecretGenerator.instance();
    }

    static TlsPreMasterSecretGenerator srp() {
        return SRPPreMasterSecretGenerator.instance();
    }
}
