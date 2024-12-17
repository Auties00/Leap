package it.auties.leap.tls.cipher.exchange;

import it.auties.leap.tls.cipher.TlsCipher;
import it.auties.leap.tls.cipher.exchange.server.*;
import it.auties.leap.tls.config.TlsVersion;
import it.auties.leap.tls.exception.TlsException;
import it.auties.leap.tls.key.TlsSupportedGroup;

import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Objects;

import static it.auties.leap.tls.BufferHelper.*;

public sealed interface TlsKeyExchangeType {
    static TlsKeyExchangeType none() {
        return null;
    }

    static TlsKeyExchangeType dh() {
        return null;
    }

    static TlsKeyExchangeType dhe() {
        return null;
    }

    static TlsKeyExchangeType eccPwd() {
        return null;
    }

    static TlsKeyExchangeType ecdh() {
        return null;
    }

    static TlsKeyExchangeType ecdhe() {
        return null;
    }

    static TlsKeyExchangeType gostr341112_256() {
        return null;
    }

    static TlsKeyExchangeType krb5() {
        return null;
    }

    static TlsKeyExchangeType psk() {
        return null;
    }

    static TlsKeyExchangeType rsa() {
        return null;
    }

    static TlsKeyExchangeType srp() {
        return null;
    }

    TlsKeyExchange newExchange();
}
