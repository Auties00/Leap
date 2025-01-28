package it.auties.leap.tls.key.implementation;

import it.auties.leap.tls.exception.TlsException;
import it.auties.leap.tls.key.TlsKeyPairGenerator;
import it.auties.leap.tls.version.TlsVersion;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.NamedParameterSpec;

public final class XDHKeyPairGenerator implements TlsKeyPairGenerator {
    private static final XDHKeyPairGenerator X25519 = new XDHKeyPairGenerator(NamedParameterSpec.X25519);
    private static final XDHKeyPairGenerator X448 = new XDHKeyPairGenerator(NamedParameterSpec.X448);

    private final NamedParameterSpec spec;

    private XDHKeyPairGenerator(NamedParameterSpec spec) {
        this.spec = spec;
    }

    public static XDHKeyPairGenerator x25519() {
        return X25519;
    }

    public static XDHKeyPairGenerator x448() {
        return X448;
    }

    @Override
    public KeyPair generate(TlsVersion version) {
        try {
            var keyPairGenerator = KeyPairGenerator.getInstance("XDH");
            keyPairGenerator.initialize(spec);
            return keyPairGenerator.genKeyPair();
        } catch (GeneralSecurityException exception) {
            throw new TlsException("Cannot generate XDH keypair", exception);
        }
    }
}
