package it.auties.leap.tls.cipher.exchange.server;

import it.auties.leap.tls.cipher.exchange.TlsKeyExchange;
import it.auties.leap.tls.cipher.exchange.client.TlsClientKeyExchange;
import it.auties.leap.tls.cipher.exchange.server.implementation.*;
import it.auties.leap.tls.ec.TlsECParameters;

import java.nio.ByteBuffer;
import java.security.PublicKey;

public non-sealed interface TlsServerKeyExchange extends TlsKeyExchange {
    static TlsServerKeyExchange none() {
        return NoneServerKeyExchange.instance();
    }

    static TlsServerKeyExchange dh(PublicKey publicKey) {
        return new DHServerKeyExchange(publicKey);
    }

    static TlsServerKeyExchange eccpwd(byte[] salt, TlsECParameters params, byte[] publicKey, byte[] password) {
        return new ECCPWDServerKeyExchange(salt, params, publicKey, password);
    }

    static TlsServerKeyExchange ecdh(TlsECParameters params, byte[] publicKey) {
        return new ECDHServerKeyExchange(params, publicKey);
    }

    static TlsServerKeyExchange psk(byte[] identityKeyHint) {
        return new PSKServerKeyExchange(identityKeyHint);
    }

    static TlsServerKeyExchange rsa(byte[] modulus, byte[] exponent) {
        return new RSAServerKeyExchange(modulus, exponent);
    }

    static TlsServerKeyExchange srp(byte[] srpN, byte[] srpG, byte[] srpS, byte[] srpB) {
        return new SRPServerKeyExchange(srpN, srpG, srpS, srpB);
    }

    @Override
    TlsServerKeyExchange decodeLocal(ByteBuffer buffer);

    @Override
    TlsClientKeyExchange decodeRemote(ByteBuffer buffer);
}
