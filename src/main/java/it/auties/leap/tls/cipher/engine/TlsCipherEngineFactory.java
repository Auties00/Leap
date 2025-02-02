package it.auties.leap.tls.cipher.engine;

import it.auties.leap.tls.cipher.engine.implementation.*;

public interface TlsCipherEngineFactory {
    static TlsCipherEngineFactory aes() {
        return AESEngine.factory();
    }

    static TlsCipherEngineFactory aria() {
        return ARIAEngine.factory();
    }

    static TlsCipherEngineFactory camellia() {
        return CamelliaEngine.factory();
    }

    static TlsCipherEngineFactory des() {
        return DESEngine.factory();
    }

    static TlsCipherEngineFactory desEde() {
        return DESEdeEngine.factory();
    }

    static TlsCipherEngineFactory idea() {
        return IDEAEngine.factory();
    }

    static TlsCipherEngineFactory kuznyechik() {
        return KuznyechikEngine.factory();
    }

    static TlsCipherEngineFactory magma() {
        return MagmaEngine.factory();
    }

    static TlsCipherEngineFactory rc2() {
        return RC2Engine.factory();
    }

    static TlsCipherEngineFactory rc4() {
        return RC4Engine.factory();
    }

    static TlsCipherEngineFactory seed() {
        return SEEDEngine.factory();
    }

    static TlsCipherEngineFactory sm4() {
        return SM4Engine.factory();
    }

    static TlsCipherEngineFactory none() {
        return NoneEngine.factory();
    }

    static TlsCipherEngineFactory chaCha20() {
        return ChaCha20Engine.factory();
    }

    TlsCipherEngine newCipherEngine();
}
