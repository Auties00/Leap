package it.auties.leap.tls.cipher.exchange.client;

import it.auties.leap.tls.cipher.exchange.TlsKeyExchange;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchangeType;
import it.auties.leap.tls.cipher.exchange.client.implementation.*;
import it.auties.leap.tls.secret.TlsPreMasterSecretGenerator;

public non-sealed abstract class TlsClientKeyExchange extends TlsKeyExchange {
    protected TlsClientKeyExchange(TlsKeyExchangeType type, TlsPreMasterSecretGenerator generator) {
        super(type, generator);
    }

    public static TlsClientKeyExchange none() {
        return NoneClientKeyExchange.instance();
    }

    public static TlsClientKeyExchange dh(byte[] publicKey) {
        return new DHClientKeyExchange(TlsKeyExchangeType.STATIC, publicKey);
    }

    public static TlsClientKeyExchange dhe(byte[] publicKey) {
        return new DHClientKeyExchange(TlsKeyExchangeType.EPHEMERAL, publicKey);
    }

    public static TlsClientKeyExchange eccpwd(byte[] publicKey, byte[] password) {
        return new ECCPWDClientKeyExchange(publicKey, password);
    }

    public static TlsClientKeyExchange ecdh(byte[] publicKey) {
        return new ECDHClientKeyExchange(TlsKeyExchangeType.STATIC, publicKey);
    }

    public static TlsClientKeyExchange ecdhe(byte[] publicKey) {
        return new ECDHClientKeyExchange(TlsKeyExchangeType.EPHEMERAL, publicKey);
    }

    public static TlsClientKeyExchange gostr256(byte[] encodedKeyTransport) {
        return new GOSTR256ClientKeyExchange(encodedKeyTransport);
    }

    public static TlsClientKeyExchange krb5(byte[] ticket, byte[] authenticator, byte[] encryptedPreMasterSecret) {
        return new KRB5ClientKeyExchange(ticket, authenticator, encryptedPreMasterSecret);
    }

    public static TlsClientKeyExchange psk(byte[] identityKey) {
        return new PSKClientKeyExchange(identityKey);
    }

    public static TlsClientKeyExchange rsa(byte[] extendedPreMasterSecret) {
        return new RSAClientKeyExchange(extendedPreMasterSecret);
    }

    public static TlsClientKeyExchange srp(byte[] srpA) {
        return new SRPClientKeyExchange(srpA);
    }
}
