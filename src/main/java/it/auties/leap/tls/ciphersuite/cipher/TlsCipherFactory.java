package it.auties.leap.tls.ciphersuite.cipher;

import it.auties.leap.tls.ciphersuite.engine.TlsCipherEngineFactory;
import it.auties.leap.tls.ciphersuite.cipher.implementation.*;

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

    static TlsCipherFactory f8() {
        return F8Cipher.factory();
    }

    TlsCipherWithEngineFactory with(TlsCipherEngineFactory factory);
}
