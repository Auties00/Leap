package it.auties.leap.tls.cipher.exchange.client;

import it.auties.leap.tls.cipher.exchange.TlsKeyExchange;
import it.auties.leap.tls.cipher.exchange.client.implementation.*;

import java.security.PublicKey;

public non-sealed interface TlsClientKeyExchange extends TlsKeyExchange {
    static TlsClientKeyExchange none() {
        return NoneClientKeyExchange.instance();
    }

    static TlsClientKeyExchange dh(PublicKey publicKey) {
        return new DHClientKeyExchange(publicKey);
    }
    static TlsClientKeyExchange eccpwd(byte[] publicKey, byte[] password) {
        return new ECCPWDClientKeyExchange(publicKey, password);
    }

    static TlsClientKeyExchange ecdh(byte[] publicKey) {
        return new ECDHClientKeyExchange(publicKey);
    }

    static TlsClientKeyExchange gostr256(byte[] encodedKeyTransport) {
        return new GOSTRClientKeyExchange(encodedKeyTransport);
    }

    static TlsClientKeyExchange krb5(byte[] ticket, byte[] authenticator, byte[] encryptedPreMasterSecret) {
        return new KRB5ClientKeyExchange(ticket, authenticator, encryptedPreMasterSecret);
    }

    static TlsClientKeyExchange psk(byte[] identityKey) {
        return new PSKClientKeyExchange(identityKey);
    }

    static TlsClientKeyExchange rsa(byte[] extendedPreMasterSecret) {
        return new RSAClientKeyExchange(extendedPreMasterSecret);
    }

    static TlsClientKeyExchange srp(byte[] srpA) {
        return new SRPClientKeyExchange(srpA);
    }
}
