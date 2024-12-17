package it.auties.leap.tls.cipher.mode;

public interface TlsCipherModeType {
    static TlsCipherModeType none() {
        return new NoneMode();
    }

    static TlsCipherModeType poly1305() {
        return new Chacha20Poly1305Mode();
    }

    static TlsCipherModeType ctr() {
        return new CtrMode();
    }

    static TlsCipherModeType gcm() {
        return new GcmMode();
    }

    static TlsCipherModeType cbc() {
        return new CbcMode();
    }

    static TlsCipherModeType cbc40() {
        return new Cbc40Mode();
    }

    static TlsCipherModeType ccm() {
        return new CcmMode();
    }

    static TlsCipherModeType ccm8() {
        return new Ccm8Mode();
    }

    static TlsCipherModeType mgmLight() {
        return new MgmLMode();
    }

    static TlsCipherModeType mgmStrong() {
        return new MgmSMode();
    }

    TlsCipherMode newInstance();
}