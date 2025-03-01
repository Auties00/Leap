package it.auties.leap.tls.cipher.exchange.factory;

import it.auties.leap.tls.cipher.exchange.TlsKeyExchange;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchangeType;
import it.auties.leap.tls.cipher.exchange.factory.implementation.*;
import it.auties.leap.tls.context.TlsContext;

import java.nio.ByteBuffer;

public interface TlsKeyExchangeFactory {
    static TlsKeyExchangeFactory none() {
        return NoneKeyExchangeFactory.ephemeralFactory();
    }

    static TlsKeyExchangeFactory dh() {
        return DHKeyExchangeFactory.staticFactory();
    }

    static TlsKeyExchangeFactory dhe() {
        return DHKeyExchangeFactory.ephemeralFactory();
    }

    static TlsKeyExchangeFactory eccpwd() {
        return ECCPWDKeyExchangeFactory.ephemeralFactory();
    }

    static TlsKeyExchangeFactory ecdh() {
        return ECDHKeyExchangeFactory.staticFactory();
    }

    static TlsKeyExchangeFactory ecdhe() {
        return ECDHKeyExchangeFactory.ephemeralFactory();
    }

    static TlsKeyExchangeFactory gostr256() {
        return GOSTR256KeyExchangeFactory.ephemeralFactory();
    }

    static TlsKeyExchangeFactory krb5() {
        return KRB5KeyExchangeFactory.ephemeralFactory();
    }

    static TlsKeyExchangeFactory psk() {
        return PSKKeyExchangeFactory.ephemeralFactory();
    }

    static TlsKeyExchangeFactory rsa() {
        return RSAKeyExchangeFactory.staticFactory();
    }

    static TlsKeyExchangeFactory srp() {
        return SRPKeyExchangeFactory.ephemeralFactory();
    }
    
    TlsKeyExchange newLocalKeyExchange(TlsContext context);
    TlsKeyExchange decodeRemoteKeyExchange(TlsContext context, ByteBuffer buffer);
    TlsKeyExchangeType type();
}
