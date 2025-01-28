package it.auties.leap.tls.key.implementation;

import it.auties.leap.tls.key.TlsKeyPairGenerator;
import it.auties.leap.tls.version.TlsVersion;

import java.security.KeyPair;

public final class UnsupportedKeyPairGenerator implements TlsKeyPairGenerator {
    private static final UnsupportedKeyPairGenerator INSTANCE = new UnsupportedKeyPairGenerator();

    private UnsupportedKeyPairGenerator() {

    }

    public static UnsupportedKeyPairGenerator instance() {
        return INSTANCE;
    }

    @Override
    public KeyPair generate(TlsVersion version) {
       throw new UnsupportedOperationException();
    }
}
