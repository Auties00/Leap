package it.auties.leap.tls.cipher;

import it.auties.leap.tls.cipher.engine.*;

public interface TlsCipherEngineFactory {
    static TlsCipherEngineFactory aes128() {
        return AESEngine.factory128();
    }

    static TlsCipherEngineFactory aes256() {
        return AESEngine.factory256();
    }

    static TlsCipherEngineFactory aria128() {
        return ARIAEngine.factory128();
    }

    static TlsCipherEngineFactory aria256() {
        return ARIAEngine.factory256();
    }

    static TlsCipherEngineFactory camellia128() {
        return CamelliaEngine.factory128();
    }

    static TlsCipherEngineFactory camellia256() {
        return CamelliaEngine.factory256();
    }

    static TlsCipherEngineFactory des40() {
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

    static TlsCipherEngineFactory rc2_40() {
        return RC2Engine.factory40();
    }

    static TlsCipherEngineFactory rc2_128() {
        return RC2Engine.factory128();
    }

    static TlsCipherEngineFactory rc4_40() {
        return RC4Engine.factory40();
    }

    static TlsCipherEngineFactory rc4_128() {
        return RC4Engine.factory128();
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
