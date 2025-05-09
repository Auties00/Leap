package it.auties.leap.tls.ciphersuite.engine;

import it.auties.leap.tls.ciphersuite.engine.implementation.*;

import java.util.OptionalInt;

public interface TlsCipherEngineFactory {
    static TlsCipherEngineFactory aes128() {
        return AesEngine.factory128();
    }

    static TlsCipherEngineFactory aes192() {
        return AesEngine.factory192();
    }

    static TlsCipherEngineFactory aes256() {
        return AesEngine.factory256();
    }

    static TlsCipherEngineFactory aria128() {
        return AriaEngine.factory128();
    }

    static TlsCipherEngineFactory aria256() {
        return AriaEngine.factory256();
    }

    static TlsCipherEngineFactory camellia128() {
        return CamelliaEngine.factory128();
    }

    static TlsCipherEngineFactory camellia256() {
        return CamelliaEngine.factory256();
    }

    static TlsCipherEngineFactory des40() {
        return DesEngine.factory();
    }

    static TlsCipherEngineFactory desEde() {
        return DesEdeEngine.factory();
    }

    static TlsCipherEngineFactory idea() {
        return IdeaEngine.factory();
    }

    static TlsCipherEngineFactory kuznyechik() {
        return KuznyechikEngine.factory();
    }

    static TlsCipherEngineFactory magma() {
        return MagmaEngine.factory();
    }

    static TlsCipherEngineFactory rc2_40() {
        return Rc2Engine.factory40();
    }

    static TlsCipherEngineFactory rc2_128() {
        return Rc2Engine.factory128();
    }

    static TlsCipherEngineFactory rc4_40() {
        return Rc4Engine.factory40();
    }

    static TlsCipherEngineFactory rc4_128() {
        return Rc4Engine.factory128();
    }

    static TlsCipherEngineFactory seed() {
        return SeedEngine.factory();
    }

    static TlsCipherEngineFactory sm4() {
        return Sm4Engine.factory();
    }

    static TlsCipherEngineFactory none() {
        return NoneEngine.factory();
    }

    static TlsCipherEngineFactory chaCha20() {
        return ChaCha20Engine.factory();
    }

    TlsCipherEngine newCipherEngine(boolean forEncryption, byte[] key);
    int keyLength();
    int blockLength();
    // FIXME: Find the correct values for this field
    default OptionalInt exportedKeyLength() {
        return OptionalInt.empty();
    }
}
