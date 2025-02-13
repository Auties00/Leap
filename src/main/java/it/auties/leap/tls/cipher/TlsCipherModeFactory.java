package it.auties.leap.tls.cipher;

import it.auties.leap.tls.cipher.mode.*;

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

    TlsCipherMode newCipherMode();
}
