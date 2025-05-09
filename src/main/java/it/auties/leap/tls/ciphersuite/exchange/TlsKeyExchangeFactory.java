package it.auties.leap.tls.ciphersuite.exchange;

import it.auties.leap.tls.ciphersuite.exchange.implementation.*;
import it.auties.leap.tls.context.TlsContext;

import java.nio.ByteBuffer;
import java.util.Optional;

public interface TlsKeyExchangeFactory {
    static TlsKeyExchangeFactory none() {
        return DHKeyExchange.staticFactory();
    }

    static TlsKeyExchangeFactory dh() {
        return DHKeyExchange.staticFactory();
    }

    static TlsKeyExchangeFactory dhe() {
        return DHKeyExchange.ephemeralFactory();
    }

    static TlsKeyExchangeFactory eccpwd() {
        return ECCPWDKeyExchange.ephemeralFactory();
    }

    static TlsKeyExchangeFactory ecdh() {
        return ECDHKeyExchange.staticFactory();
    }

    static TlsKeyExchangeFactory ecdhe() {
        return ECDHKeyExchange.ephemeralFactory();
    }

    static TlsKeyExchangeFactory gostr256() {
        return GOSTR256KeyExchange.ephemeralFactory();
    }

    static TlsKeyExchangeFactory krb5() {
        return KRB5KeyExchange.ephemeralFactory();
    }

    static TlsKeyExchangeFactory psk() {
        return PSKKeyExchange.ephemeralFactory();
    }

    static TlsKeyExchangeFactory rsa() {
        return RSAKeyExchange.staticFactory();
    }

    static TlsKeyExchangeFactory srp() {
        return SRPKeyExchange.ephemeralFactory();
    }
    
    Optional<TlsKeyExchange> newLocalKeyExchange(TlsContext context);
    Optional<TlsKeyExchange> newRemoteKeyExchange(TlsContext context, ByteBuffer source);
    TlsKeyExchangeType type();
}
