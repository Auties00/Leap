package it.auties.leap.tls.cipher.mode;

import it.auties.leap.tls.cipher.engine.TlsCipherEngine;
import it.auties.leap.tls.cipher.mode.implementation.*;
import it.auties.leap.tls.hash.TlsExchangeAuthenticator;
import it.auties.leap.tls.version.TlsVersion;

@FunctionalInterface
public interface TlsCipherModeFactory {
    static TlsCipherModeFactory poly1305() {
        return Poly1305Mode.factory();
    }

    static TlsCipherModeFactory ctr() {
        return CTRMode.factory();
    }

    static TlsCipherModeFactory gcm() {
        return GCMMode.factory();
    }

    static TlsCipherModeFactory cbc() {
        return CBCMode.factory();
    }

    static TlsCipherModeFactory cbcExport() {
        return CBCMode.factory();
    }

    static TlsCipherModeFactory ccm() {
        return CCMMode.factory();
    }

    static TlsCipherModeFactory ccm8() {
        return CCMMode.factory();
    }

    static TlsCipherModeFactory none() {
        return NoneMode.factory();
    }

    static TlsCipherModeFactory mgmLight() {
        return (version, authenticator, engine, fixedIv) -> {
            throw new UnsupportedOperationException();
        };
    }

    static TlsCipherModeFactory mgmStrong() {
        return (version, authenticator, engine, fixedIv) -> {
            throw new UnsupportedOperationException();
        };
    }

    static TlsCipherModeFactory cntImit() {
        return (version, authenticator, engine, fixedIv) -> {
            throw new UnsupportedOperationException();
        };
    }

    static TlsCipherModeFactory ctrOmac() {
        return (version, authenticator, engine, fixedIv) -> {
            throw new UnsupportedOperationException();
        };
    }

    TlsCipherMode newCipherMode(TlsVersion version, TlsExchangeAuthenticator authenticator, TlsCipherEngine engine, byte[] fixedIv);
}
