package it.auties.leap.tls.cipher.mode;

import it.auties.leap.tls.cipher.engine.TlsCipherEngineFactory;
import it.auties.leap.tls.cipher.mode.implementation.*;

public interface TlsCipherFactory {
    static TlsCipherFactory poly1305() {
        return Poly1305Cipher.factory();
    }

    static TlsCipherFactory ctr() {
        return CtrCipher.factory();
    }

    static TlsCipherFactory gcm() {
        return GcmCipher.factory();
    }

    static TlsCipherFactory cbc() {
        return CbcCipher.factory();
    }

    static TlsCipherFactory cbcExport() {
        return CbcCipher.factory();
    }

    static TlsCipherFactory ccm() {
        return CcmCipher.factory();
    }

    static TlsCipherFactory ccm8() {
        return CcmCipher.factory();
    }

    static TlsCipherFactory none() {
        return NoneCipher.factory();
    }

    static TlsCipherFactory mgmLight() {
        return MgmLightCipher.factory();
    }

    static TlsCipherFactory mgmStrong() {
        return MgmStrongCipher.factory();
    }

    static TlsCipherFactory cntImit() {
        return CntImitCipher.factory();
    }

    static TlsCipherFactory ctrOmac() {
        return CtrOmacCipher.factory();
    }

    TlsCipherWithEngineFactory with(TlsCipherEngineFactory factory);
}
