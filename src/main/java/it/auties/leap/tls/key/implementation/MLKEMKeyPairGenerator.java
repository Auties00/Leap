package it.auties.leap.tls.key.implementation;

import it.auties.leap.tls.exception.TlsException;
import it.auties.leap.tls.key.TlsKeyPairGenerator;
import it.auties.leap.tls.version.TlsVersion;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.NamedParameterSpec;

public final class MLKEMKeyPairGenerator implements TlsKeyPairGenerator {
    private static final MLKEMKeyPairGenerator ML_KEM_512 = new MLKEMKeyPairGenerator(NamedParameterSpec.ML_KEM_512);
    private static final MLKEMKeyPairGenerator ML_KEM_768 = new MLKEMKeyPairGenerator(NamedParameterSpec.ML_KEM_768);
    private static final MLKEMKeyPairGenerator ML_KEM_1024 = new MLKEMKeyPairGenerator(NamedParameterSpec.ML_KEM_1024);

    private final NamedParameterSpec spec;

    private MLKEMKeyPairGenerator(NamedParameterSpec spec) {
        this.spec = spec;
    }

    public static MLKEMKeyPairGenerator mlKem512() {
        return ML_KEM_512;
    }

    public static MLKEMKeyPairGenerator mlKem768() {
        return ML_KEM_768;
    }

    public static MLKEMKeyPairGenerator mlKem1024() {
        return ML_KEM_1024;
    }

    @Override
    public KeyPair generate(TlsVersion version) {
        try {
            var keyPairGenerator = KeyPairGenerator.getInstance("ML-KEM");
            keyPairGenerator.initialize(spec);
            return keyPairGenerator.generateKeyPair();
        } catch (GeneralSecurityException exception) {
            throw new TlsException("Cannot generate ML-KEM keypair", exception);
        }
    }
}
