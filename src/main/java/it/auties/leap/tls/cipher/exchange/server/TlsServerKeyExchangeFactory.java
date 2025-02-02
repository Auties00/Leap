package it.auties.leap.tls.cipher.exchange.server;

import it.auties.leap.tls.TlsEngine;
import it.auties.leap.tls.cipher.exchange.server.implementation.*;

public interface TlsServerKeyExchangeFactory {
    static TlsServerKeyExchangeFactory none() {
        return NoneServerKeyExchange.factory();
    }

    static TlsServerKeyExchangeFactory dh() {
        return DHServerKeyExchange.factory();
    }

    static TlsServerKeyExchangeFactory dhe() {
        return DHEServerKeyExchange.factory();
    }

    static TlsServerKeyExchangeFactory eccpwd() {
        return ECCPWDServerKeyExchange.factory();
    }

    static TlsServerKeyExchangeFactory ecdh() {
        return ECDHServerKeyExchange.factory();
    }

    static TlsServerKeyExchangeFactory ecdhe() {
        return ECDHEServerKeyExchange.factory();
    }

    static TlsServerKeyExchangeFactory psk() {
        return PSKServerKeyExchange.factory();
    }

    static TlsServerKeyExchangeFactory rsa() {
        return RSAServerKeyExchange.factory();
    }

    static TlsServerKeyExchangeFactory srp() {
        return SRPServerKeyExchange.factory();
    }

    TlsServerKeyExchange newServerKeyExchange(TlsEngine engine);
}
