package it.auties.leap.tls.group;

import it.auties.leap.tls.cipher.exchange.server.TlsServerKeyExchange;
import it.auties.leap.tls.group.implementation.NamedFiniteField;

public non-sealed interface TlsSupportedFiniteField extends TlsSupportedGroup {
    static TlsSupportedFiniteField ffdhe2048() {
        return NamedFiniteField.ffdhe2048();
    }

    static TlsSupportedFiniteField ffdhe3072() {
        return NamedFiniteField.ffdhe3072();
    }

    static TlsSupportedFiniteField ffdhe4096() {
        return NamedFiniteField.ffdhe4096();
    }

    static TlsSupportedFiniteField ffdhe6144() {
        return NamedFiniteField.ffdhe6144();
    }

    static TlsSupportedFiniteField ffdhe8192() {
        return NamedFiniteField.ffdhe8192();
    }

    boolean accepts(TlsServerKeyExchange exchange);
}
