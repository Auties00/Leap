package it.auties.leap.tls.key.group;

import it.auties.leap.tls.TlsContext;
import it.auties.leap.tls.cipher.exchange.client.ECDHClientKeyExchange;
import it.auties.leap.tls.cipher.exchange.server.ECDHServerKeyExchange;
import it.auties.leap.tls.ec.TlsECParameters;
import it.auties.leap.tls.ec.TlsECParametersDeserializer;
import it.auties.leap.tls.ec.implementation.NamedCurveParameters;
import it.auties.leap.tls.exception.TlsException;
import it.auties.leap.tls.key.TlsSupportedCurve;
import it.auties.leap.tls.util.KeyUtils;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;

import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import java.security.*;
import java.security.interfaces.XECPublicKey;
import java.security.spec.*;

public final class NamedCurve implements TlsSupportedCurve {
    private static final NamedCurve SECT163K1 = new NamedCurve(1, true, "ECDSA", ECNamedCurveTable.getParameterSpec("sect163k1"));
    private static final NamedCurve SECT163R1 = new NamedCurve(2, true, "ECDSA", ECNamedCurveTable.getParameterSpec("sect163r1"));
    private static final NamedCurve SECT163R2 = new NamedCurve(3, true, "ECDSA", ECNamedCurveTable.getParameterSpec("sect163r2"));
    private static final NamedCurve SECT193R1 = new NamedCurve(4, true, "ECDSA", ECNamedCurveTable.getParameterSpec("sect193r1"));
    private static final NamedCurve SECT193R2 = new NamedCurve(5, true, "ECDSA", ECNamedCurveTable.getParameterSpec("sect193r2"));
    private static final NamedCurve SECT233K1 = new NamedCurve(6, true, "ECDSA", ECNamedCurveTable.getParameterSpec("sect233k1"));
    private static final NamedCurve SECT233R1 = new NamedCurve(7, true, "ECDSA", ECNamedCurveTable.getParameterSpec("sect233r1"));
    private static final NamedCurve SECT239K1 = new NamedCurve(8, true, "ECDSA", ECNamedCurveTable.getParameterSpec("sect239k1"));
    private static final NamedCurve SECT283K1 = new NamedCurve(9, true, "ECDSA", ECNamedCurveTable.getParameterSpec("sect283k1"));
    private static final NamedCurve SECT283R1 = new NamedCurve(10, true, "ECDSA", ECNamedCurveTable.getParameterSpec("sect283r1"));
    private static final NamedCurve SECT409K1 = new NamedCurve(11, true, "ECDSA", ECNamedCurveTable.getParameterSpec("sect409k1"));
    private static final NamedCurve SECT409R1 = new NamedCurve(12, true, "ECDSA", ECNamedCurveTable.getParameterSpec("sect409r1"));
    private static final NamedCurve SECT571K1 = new NamedCurve(13, true, "ECDSA", ECNamedCurveTable.getParameterSpec("sect571k1"));
    private static final NamedCurve SECT571R1 = new NamedCurve(14, true, "ECDSA", ECNamedCurveTable.getParameterSpec("sect571r1"));
    private static final NamedCurve SECP160K1 = new NamedCurve(15, true, "ECDSA", ECNamedCurveTable.getParameterSpec("secp160k1"));
    private static final NamedCurve SECP160R1 = new NamedCurve(16, true, "ECDSA", ECNamedCurveTable.getParameterSpec("secp160r1"));
    private static final NamedCurve SECP160R2 = new NamedCurve(17, true, "ECDSA", ECNamedCurveTable.getParameterSpec("secp160r2"));
    private static final NamedCurve SECP192K1 = new NamedCurve(18, true, "ECDSA", ECNamedCurveTable.getParameterSpec("secp192k1"));
    private static final NamedCurve SECP192R1 = new NamedCurve(19, true, "ECDSA", ECNamedCurveTable.getParameterSpec("secp192r1"));
    private static final NamedCurve SECP224K1 = new NamedCurve(20, true, "ECDSA", ECNamedCurveTable.getParameterSpec("secp224k1"));
    private static final NamedCurve SECP224R1 = new NamedCurve(21, true, "ECDSA", ECNamedCurveTable.getParameterSpec("secp224r1"));
    private static final NamedCurve SECP256K1 = new NamedCurve(22, true, "ECDSA", ECNamedCurveTable.getParameterSpec("secp256k1"));
    private static final NamedCurve SECP256R1 = new NamedCurve(23, true, "ECDSA", ECNamedCurveTable.getParameterSpec("secp256r1"));
    private static final NamedCurve SECP384R1 = new NamedCurve(24, true, "ECDSA", ECNamedCurveTable.getParameterSpec("secp384r1"));
    private static final NamedCurve SECP521R1 = new NamedCurve(25, true, "ECDSA", ECNamedCurveTable.getParameterSpec("secp521r1"));
    private static final NamedCurve BRAINPOOLP256R1 = new NamedCurve(26, true, "ECDSA", ECNamedCurveTable.getParameterSpec("brainpoolp256r1"));
    private static final NamedCurve BRAINPOOLP384R1 = new NamedCurve(27, true, "ECDSA", ECNamedCurveTable.getParameterSpec("brainpoolp384r1"));
    private static final NamedCurve BRAINPOOLP512R1 = new NamedCurve(28, true, "ECDSA", ECNamedCurveTable.getParameterSpec("brainpoolp512r1"));
    private static final NamedCurve X25519 = new NamedCurve(29, true, "XDH", NamedParameterSpec.X25519);
    private static final NamedCurve X448 = new NamedCurve(30, true, "XDH", NamedParameterSpec.X448);
    private static final NamedCurve BRAINPOOLP256R1TLS13 = new NamedCurve(31, true, "ECDSA", ECNamedCurveTable.getParameterSpec("brainpoolp256r1"));
    private static final NamedCurve BRAINPOOLP384R1TLS13 = new NamedCurve(32, true, "ECDSA", ECNamedCurveTable.getParameterSpec("brainpoolp384r1"));
    private static final NamedCurve BRAINPOOLP512R1TLS13 = new NamedCurve(33, true, "ECDSA", ECNamedCurveTable.getParameterSpec("brainpoolp512r1"));
    private static final NamedCurve GC256A = new NamedCurve(34, true, "ECDSA", ECNamedCurveTable.getParameterSpec("gc256a"));
    private static final NamedCurve GC256B = new NamedCurve(35, true, "ECDSA", ECNamedCurveTable.getParameterSpec("gc256b"));
    private static final NamedCurve GC256C = new NamedCurve(36, true, "ECDSA", ECNamedCurveTable.getParameterSpec("gc256c"));
    private static final NamedCurve GC256D = new NamedCurve(37, true, "ECDSA", ECNamedCurveTable.getParameterSpec("gc256d"));
    private static final NamedCurve GC512A = new NamedCurve(38, true, "ECDSA", ECNamedCurveTable.getParameterSpec("gc512a"));
    private static final NamedCurve GC512B = new NamedCurve(39, true, "ECDSA", ECNamedCurveTable.getParameterSpec("gc512b"));
    private static final NamedCurve GC512C = new NamedCurve(40, false, "ECDSA", ECNamedCurveTable.getParameterSpec("gc512c"));
    private static final NamedCurve CURVESM2 = new NamedCurve(41, true, "XDH", NamedParameterSpec.X25519);
    private static final NamedCurve ML_KEM_512 = new NamedCurve(512, true, "ML-KEM", NamedParameterSpec.ML_KEM_512);
    private static final NamedCurve ML_KEM_768 = new NamedCurve(513, true, "ML-KEM", NamedParameterSpec.ML_KEM_768);
    private static final NamedCurve ML_KEM_1024 = new NamedCurve(514, true, "ML-KEM", NamedParameterSpec.ML_KEM_1024);
    private static final NamedCurve X25519MLKEM768 = new NamedCurve(4588, true, "XDH", NamedParameterSpec.X25519);
    private static final NamedCurve SECP256R1MLKEM768 = new NamedCurve(4587, true, "ECDSA", ECNamedCurveTable.getParameterSpec("secp256r1"));

    public static NamedCurve sect163k1() {
        return SECT163K1;
    }

    public static NamedCurve sect163r1() {
        return SECT163R1;
    }

    public static NamedCurve sect163r2() {
        return SECT163R2;
    }

    public static NamedCurve sect193r1() {
        return SECT193R1;
    }

    public static NamedCurve sect193r2() {
        return SECT193R2;
    }

    public static NamedCurve sect233k1() {
        return SECT233K1;
    }

    public static NamedCurve sect233r1() {
        return SECT233R1;
    }

    public static NamedCurve sect239k1() {
        return SECT239K1;
    }

    public static NamedCurve sect283k1() {
        return SECT283K1;
    }

    public static NamedCurve sect283r1() {
        return SECT283R1;
    }

    public static NamedCurve sect409k1() {
        return SECT409K1;
    }

    public static NamedCurve sect409r1() {
        return SECT409R1;
    }

    public static NamedCurve sect571k1() {
        return SECT571K1;
    }

    public static NamedCurve sect571r1() {
        return SECT571R1;
    }

    public static NamedCurve secp160k1() {
        return SECP160K1;
    }

    public static NamedCurve secp160r1() {
        return SECP160R1;
    }

    public static NamedCurve secp160r2() {
        return SECP160R2;
    }

    public static NamedCurve secp192k1() {
        return SECP192K1;
    }

    public static NamedCurve secp192r1() {
        return SECP192R1;
    }

    public static NamedCurve secp224k1() {
        return SECP224K1;
    }

    public static NamedCurve secp224r1() {
        return SECP224R1;
    }

    public static NamedCurve secp256k1() {
        return SECP256K1;
    }

    public static NamedCurve secp256r1() {
        return SECP256R1;
    }

    public static NamedCurve secp384r1() {
        return SECP384R1;
    }

    public static NamedCurve secp521r1() {
        return SECP521R1;
    }

    public static NamedCurve brainpoolp256r1() {
        return BRAINPOOLP256R1;
    }

    public static NamedCurve brainpoolp384r1() {
        return BRAINPOOLP384R1;
    }

    public static NamedCurve brainpoolp512r1() {
        return BRAINPOOLP512R1;
    }

    public static NamedCurve gc256a() {
        return GC256A;
    }

    public static NamedCurve gc256b() {
        return GC256B;
    }

    public static NamedCurve gc256c() {
        return GC256C;
    }

    public static NamedCurve gc256d() {
        return GC256D;
    }

    public static NamedCurve gc512a() {
        return GC512A;
    }

    public static NamedCurve gc512b() {
        return GC512B;
    }

    public static NamedCurve gc512c() {
        return GC512C;
    }

    public static NamedCurve x25519() {
        return X25519;
    }

    public static NamedCurve x448() {
        return X448;
    }

    public static NamedCurve mlKem512() {
        return ML_KEM_512;
    }

    public static NamedCurve mlKem768() {
        return ML_KEM_768;
    }

    public static NamedCurve mlKem1024() {
        return ML_KEM_1024;
    }

    public static NamedCurve x25519MlKem768() {
        return X25519MLKEM768;
    }

    public static NamedCurve secp256r1MlKem768() {
        return SECP256R1MLKEM768;
    }

    public static NamedCurve brainpoolp256r1Tls13() {
        return BRAINPOOLP256R1TLS13;
    }

    public static NamedCurve brainpoolp384r1Tls13() {
        return BRAINPOOLP384R1TLS13;
    }

    public static NamedCurve brainpoolp512r1Tls13() {
        return BRAINPOOLP512R1TLS13;
    }
    
    private final int id;
    private final boolean dtls;
    private final String algorithm;
    private final AlgorithmParameterSpec spec;

    private NamedCurve(int id, boolean dtls, String algorithm, AlgorithmParameterSpec spec) {
        this.id = id;
        this.dtls = dtls;
        this.algorithm = algorithm;
        this.spec = spec;
    }

    @Override
    public int id() {
        return id;
    }

    @Override
    public boolean dtls() {
        return dtls;
    }

    @Override
    public TlsECParameters toParameters() {
        return new NamedCurveParameters(id);
    }

    @Override
    public TlsECParametersDeserializer parametersDeserializer() {
        return TlsECParametersDeserializer.namedCurve();
    }

    public KeyPair generateLocalKeyPair(TlsContext context) {
        try {
            var keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
            keyPairGenerator.initialize(spec);
            return keyPairGenerator.generateKeyPair();
        } catch (GeneralSecurityException exception) {
            throw new TlsException("Cannot generate EC keypair", exception);
        }
    }

    private PublicKey parseRemotePublicKey(TlsContext context) {
        var mode = context.selectedMode()
                .orElseThrow(() -> new TlsException("No mode was selected"));
        var remoteKeyExchange = context.remoteKeyExchange()
                .orElseThrow(() -> new TlsException("Missing remote key exchange"));
        try {
            return switch (spec) {
                case ECNamedCurveParameterSpec bcSpec -> {
                    var key = switch (mode) {
                        case CLIENT -> {
                            if(!(remoteKeyExchange instanceof ECDHServerKeyExchange serverKeyExchange)) {
                                throw new TlsException("Unsupported key type");
                            }
                            yield serverKeyExchange.publicKey();
                        }
                        case SERVER -> {
                            if(!(remoteKeyExchange instanceof ECDHClientKeyExchange clientKeyExchange)) {
                                throw new TlsException("Unsupported key type");
                            }
                            yield clientKeyExchange.publicKey();
                        }
                    };
                    var curve = bcSpec.getCurve();
                    var bcPoint = curve.decodePoint(key);
                    var x = bcPoint.getAffineXCoord().toBigInteger();
                    var y = bcPoint.getAffineYCoord().toBigInteger();
                    var w = new ECPoint(x, y);
                    var ellipticCurve = new EllipticCurve(new ECFieldFp(curve.getField().getCharacteristic()), curve.getA().toBigInteger(), curve.getB().toBigInteger());
                    var generator = new ECPoint(bcSpec.getG().getAffineXCoord().toBigInteger(), bcSpec.getG().getAffineYCoord().toBigInteger());
                    var params = new ECParameterSpec(ellipticCurve, generator, bcSpec.getN(), bcSpec.getH().intValue());
                    var pubKeySpec = new ECPublicKeySpec(w, params);
                    var keyFactory = KeyFactory.getInstance(algorithm);
                    yield keyFactory.generatePublic(pubKeySpec);
                }
                case NamedParameterSpec namedParameterSpec -> {
                    var key = switch (mode) {
                        case CLIENT -> {
                            if(!(remoteKeyExchange instanceof ECDHServerKeyExchange serverKeyExchange)) {
                                throw new TlsException("Unsupported key type");
                            }
                            yield serverKeyExchange.publicKey();
                        }
                        case SERVER -> {
                            if(!(remoteKeyExchange instanceof ECDHClientKeyExchange clientKeyExchange)) {
                                throw new TlsException("Unsupported key type");
                            }
                            yield clientKeyExchange.publicKey();
                        }
                    };
                    var keyFactory = KeyFactory.getInstance(algorithm);
                    var xecPublicKeySpec = new XECPublicKeySpec(namedParameterSpec, KeyUtils.fromUnsignedLittleEndianBytes(key));
                    yield keyFactory.generatePublic(xecPublicKeySpec);
                }
                default -> throw new TlsException("Unsupported spec");
            };
        } catch (NoSuchAlgorithmException exception) {
            throw new TlsException("Missing DH implementation", exception);
        } catch (GeneralSecurityException exception) {
            throw new TlsException("Cannot parse public DH key", exception);
        }
    }

    @Override
    public byte[] dumpLocalPublicKey(TlsContext context) {
        var localKeyPair = context.localKeyPair()
                .orElseThrow(() -> new TlsException("No mode was selected"));
        return switch (localKeyPair.getPublic()) {
            case XECPublicKey publicKey -> KeyUtils.toUnsignedLittleEndianBytes(publicKey.getU());
            case DHPublicKey publicKey -> KeyUtils.toUnsignedLittleEndianBytes(publicKey.getY());
            case ECPublicKey publicKey -> publicKey.getQ().getEncoded(false);
            default -> throw new TlsException("Unsupported key type");
        };
    }

    @Override
    public byte[] computeSharedSecret(TlsContext context) {
        var privateKey = context.localKeyPair()
                .orElseThrow(() -> new TlsException("Missing local key pair"))
                .getPrivate();
        var keyExchangeType = context.negotiatedCipher()
                .orElseThrow(() -> new TlsException("Missing negotiated cipher"))
                .keyExchangeFactory()
                .type();
        var publicKey = switch (keyExchangeType) {
            case STATIC -> context.remotePublicKey()
                    .orElseThrow(() -> new TlsException("Missing remote public key for static pre master secret generation"));
            case EPHEMERAL -> parseRemotePublicKey(context);
        };
        try {
            var keyAgreement = KeyAgreement.getInstance(algorithm);
            keyAgreement.init(privateKey, spec);
            keyAgreement.doPhase(publicKey, true);
            return keyAgreement.generateSecret();
        }catch (GeneralSecurityException exception) {
            throw new TlsException("Cannot compute shared secret", exception);
        }
    }
}
