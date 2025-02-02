package it.auties.leap.tls.cipher.exchange.client;

import it.auties.leap.tls.TlsEngine;
import it.auties.leap.tls.cipher.exchange.client.implementation.*;

public interface TlsClientKeyExchangeFactory {
    static TlsClientKeyExchangeFactory none() {
        return NoneClientKeyExchange.factory();
    }

    static TlsClientKeyExchangeFactory dh() {
        return DHClientKeyExchange.factory();
    }

    static TlsClientKeyExchangeFactory dhe() {
        return DHEClientKeyExchange.factory();
    }

    static TlsClientKeyExchangeFactory eccpwd() {
        return ECCPWDClientKeyExchange.factory();
    }

    static TlsClientKeyExchangeFactory ecdh() {
        return ECDHClientKeyExchange.factory();
    }

    static TlsClientKeyExchangeFactory ecdhe() {
        return ECDHEClientKeyExchange.factory();
    }

    static TlsClientKeyExchangeFactory gostr256() {
        return GOSTRClientKeyExchange.factory();
    }

    static TlsClientKeyExchangeFactory krb5() {
        return KRB5ClientKeyExchange.factory();
    }

    static TlsClientKeyExchangeFactory psk() {
        return PSKClientKeyExchange.factory();
    }

    static TlsClientKeyExchangeFactory rsa() {
        return RSAClientKeyExchange.factory();
    }

    static TlsClientKeyExchangeFactory srp() {
        return SRPClientKeyExchange.factory();
    }
    
    TlsClientKeyExchange newClientKeyExchange(TlsEngine engine);
}
