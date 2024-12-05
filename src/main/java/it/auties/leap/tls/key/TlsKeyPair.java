package it.auties.leap.tls.key;

import it.auties.leap.tls.TlsSupportedGroup;

import javax.crypto.spec.DHParameterSpec;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.XECPublicKey;
import java.security.spec.NamedParameterSpec;

public record TlsKeyPair(byte[] rawPublicKey, TlsSupportedGroup group, KeyPair keyPair) {
    public static TlsKeyPair random(TlsSupportedGroup namedGroup) {
        try {
            return switch (namedGroup) {
                case X25519 -> generateEllipticCurveDiffieHellmanKeyPair(NamedParameterSpec.X25519, 32, TlsSupportedGroup.X25519);
                case X448 -> generateEllipticCurveDiffieHellmanKeyPair(NamedParameterSpec.X448, 56, TlsSupportedGroup.X448);

                case SECT163K1, SECT163R1, SECT163R2,
                     SECT193R1, SECT193R2, SECT233K1, SECT233R1, SECT239K1,
                     SECT283K1, SECT283R1, SECT409K1, SECT409R1, SECT571K1,
                     SECT571R1, SECP160K1, SECP160R1, SECP160R2, SECP192K1,
                     SECP192R1, SECP224K1, SECP224R1, SECP256K1, SECP256R1,
                     SECP384R1, SECP521R1 -> generateEllipticCurveDiffieHellmanKeyPair(null, 0, namedGroup);

                case FFDHE2048 -> generateFiniteFieldDiffieHellmanKeyPair(2048, namedGroup);
                case FFDHE3072 -> generateFiniteFieldDiffieHellmanKeyPair(3072, namedGroup);
                case FFDHE4096 -> generateFiniteFieldDiffieHellmanKeyPair(4096, namedGroup);
                case FFDHE6144 -> generateFiniteFieldDiffieHellmanKeyPair(6144, namedGroup);
                case FFDHE8192 -> generateFiniteFieldDiffieHellmanKeyPair(8192, namedGroup);

                default -> throw new IllegalArgumentException("%s is not supported".formatted(namedGroup));
            };
        }catch (GeneralSecurityException exception) {
            throw new IllegalStateException("Cannot generate key pair", exception);
        }
    }

    private static TlsKeyPair generateFiniteFieldDiffieHellmanKeyPair(int keySize, TlsSupportedGroup namedGroup) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        var secureRandom = new SecureRandom();
        var p = BigInteger.probablePrime(keySize, secureRandom);
        var g = BigInteger.valueOf(2);
        var dhParameterSpec = new DHParameterSpec(p, g);
        var keyPairGenerator = KeyPairGenerator.getInstance("DH");
        keyPairGenerator.initialize(dhParameterSpec);
        var keyPair = keyPairGenerator.generateKeyPair();
        return new TlsKeyPair(keyPair.getPublic().getEncoded(), namedGroup, keyPair);
    }

    private static TlsKeyPair generateEllipticCurveDiffieHellmanKeyPair(NamedParameterSpec spec, int keySize, TlsSupportedGroup namedGroup) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        var generator = KeyPairGenerator.getInstance("XDH");
        generator.initialize(spec);
        var keyPair = generator.genKeyPair();
        var rawPublicKey = new byte[keySize];
        var arr = ((XECPublicKey) keyPair.getPublic()).getU().toByteArray();
        try {
            for(var i = 0; i < rawPublicKey.length; i++) {
                rawPublicKey[i] = arr[arr.length - i - 1]; // Ignores left padding automatically
            }
        }catch (Throwable throwable) {
            throw new RuntimeException();
        }
        return new TlsKeyPair(rawPublicKey, namedGroup, keyPair);
    }
}
