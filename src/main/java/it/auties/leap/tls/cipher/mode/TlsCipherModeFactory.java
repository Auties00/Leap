package it.auties.leap.tls.cipher.mode;

import it.auties.leap.tls.cipher.engine.TlsCipherEngine;
import it.auties.leap.tls.cipher.exchange.TlsExchangeMac;
import it.auties.leap.tls.cipher.mode.implementation.*;

public sealed interface TlsCipherModeFactory {
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
        return MGMLightMode.factory();
    }

    static TlsCipherModeFactory mgmStrong() {
        return MGMStrongMode.factory();
    }

    static TlsCipherModeFactory cntImit() {
        return CNTImitMode.factory();
    }

    static TlsCipherModeFactory ctrOmac() {
        return CTROMacMode.factory();
    }

    non-sealed interface Block extends TlsCipherModeFactory {
        TlsCipherMode newCipherMode(TlsCipherEngine.Block engine, byte[] fixedIv, TlsExchangeMac authenticator);
        int ivLength(TlsCipherEngine.Block engine);
        int fixedIvLength(TlsCipherEngine.Block engine);
        int tagLength(TlsCipherEngine.Block engine);
    }

    non-sealed interface Stream extends TlsCipherModeFactory {
        TlsCipherMode newCipherMode(TlsCipherEngine.Stream engine, byte[] fixedIv, TlsExchangeMac authenticator);
        int ivLength(TlsCipherEngine.Stream engine);
        int fixedIvLength(TlsCipherEngine.Stream engine);
        int tagLength(TlsCipherEngine.Stream engine);
    }
}
