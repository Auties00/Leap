package it.auties.leap.tls.cipher.exchange;

import it.auties.leap.tls.cipher.exchange.server.*;
import it.auties.leap.tls.ec.TlsECParameters;
import it.auties.leap.tls.key.TlsPreMasterSecretGenerator;

import java.security.PublicKey;

public non-sealed abstract class TlsServerKeyExchange extends TlsKeyExchange {
    protected TlsServerKeyExchange(TlsKeyExchangeType type, TlsPreMasterSecretGenerator generator) {
        super(type, generator);
    }

    public static TlsServerKeyExchange none() {
        return NoneServerKeyExchange.instance();
    }

    public static TlsServerKeyExchange dh(PublicKey publicKey) {
        return new DHServerKeyExchange(TlsKeyExchangeType.STATIC, publicKey);
    }

    public static TlsServerKeyExchange dhe(PublicKey publicKey) {
        return new DHServerKeyExchange(TlsKeyExchangeType.EPHEMERAL, publicKey);
    }

    public static TlsServerKeyExchange eccpwd(byte[] salt, TlsECParameters params, byte[] publicKey, byte[] password) {
        return new ECCPWDServerKeyExchange(salt, params, publicKey, password);
    }

    public static TlsServerKeyExchange ecdh(TlsECParameters params, byte[] publicKey) {
        return new ECDHServerKeyExchange(TlsKeyExchangeType.STATIC, params, publicKey);
    }

    public static TlsServerKeyExchange ecdhe(TlsECParameters params, byte[] publicKey) {
        return new ECDHServerKeyExchange(TlsKeyExchangeType.EPHEMERAL, params, publicKey);
    }

    public static TlsServerKeyExchange psk(byte[] identityKeyHint) {
        return new PSKServerKeyExchange(identityKeyHint);
    }

    public static TlsServerKeyExchange rsa(byte[] modulus, byte[] exponent) {
        return new RSAServerKeyExchange(modulus, exponent);
    }

    public static TlsServerKeyExchange srp(byte[] srpN, byte[] srpG, byte[] srpS, byte[] srpB) {
        return new SRPServerKeyExchange(srpN, srpG, srpS, srpB);
    }
}
