package it.auties.leap.tls.group.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.connection.TlsConnection;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.ec.TlsECParameters;
import it.auties.leap.tls.ec.TlsECParametersDeserializer;
import it.auties.leap.tls.ec.implementation.NamedCurveParameters;
import it.auties.leap.tls.group.TlsSupportedEllipticCurve;
import it.auties.leap.tls.property.TlsProperty;
import it.auties.leap.tls.secret.TlsSecret;
import it.auties.leap.tls.util.ECKeyUtils;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;

import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import java.security.*;
import java.security.cert.Certificate;
import java.security.interfaces.XECPublicKey;
import java.security.spec.*;

public final class NamedEllipticCurve implements TlsSupportedEllipticCurve {
    private static final NamedEllipticCurve SECT163K1 = new NamedEllipticCurve(1, true, "ECDSA", ECNamedCurveTable.getParameterSpec("sect163k1"));
    private static final NamedEllipticCurve SECT163R1 = new NamedEllipticCurve(2, true, "ECDSA", ECNamedCurveTable.getParameterSpec("sect163r1"));
    private static final NamedEllipticCurve SECT163R2 = new NamedEllipticCurve(3, true, "ECDSA", ECNamedCurveTable.getParameterSpec("sect163r2"));
    private static final NamedEllipticCurve SECT193R1 = new NamedEllipticCurve(4, true, "ECDSA", ECNamedCurveTable.getParameterSpec("sect193r1"));
    private static final NamedEllipticCurve SECT193R2 = new NamedEllipticCurve(5, true, "ECDSA", ECNamedCurveTable.getParameterSpec("sect193r2"));
    private static final NamedEllipticCurve SECT233K1 = new NamedEllipticCurve(6, true, "ECDSA", ECNamedCurveTable.getParameterSpec("sect233k1"));
    private static final NamedEllipticCurve SECT233R1 = new NamedEllipticCurve(7, true, "ECDSA", ECNamedCurveTable.getParameterSpec("sect233r1"));
    private static final NamedEllipticCurve SECT239K1 = new NamedEllipticCurve(8, true, "ECDSA", ECNamedCurveTable.getParameterSpec("sect239k1"));
    private static final NamedEllipticCurve SECT283K1 = new NamedEllipticCurve(9, true, "ECDSA", ECNamedCurveTable.getParameterSpec("sect283k1"));
    private static final NamedEllipticCurve SECT283R1 = new NamedEllipticCurve(10, true, "ECDSA", ECNamedCurveTable.getParameterSpec("sect283r1"));
    private static final NamedEllipticCurve SECT409K1 = new NamedEllipticCurve(11, true, "ECDSA", ECNamedCurveTable.getParameterSpec("sect409k1"));
    private static final NamedEllipticCurve SECT409R1 = new NamedEllipticCurve(12, true, "ECDSA", ECNamedCurveTable.getParameterSpec("sect409r1"));
    private static final NamedEllipticCurve SECT571K1 = new NamedEllipticCurve(13, true, "ECDSA", ECNamedCurveTable.getParameterSpec("sect571k1"));
    private static final NamedEllipticCurve SECT571R1 = new NamedEllipticCurve(14, true, "ECDSA", ECNamedCurveTable.getParameterSpec("sect571r1"));
    private static final NamedEllipticCurve SECP160K1 = new NamedEllipticCurve(15, true, "ECDSA", ECNamedCurveTable.getParameterSpec("secp160k1"));
    private static final NamedEllipticCurve SECP160R1 = new NamedEllipticCurve(16, true, "ECDSA", ECNamedCurveTable.getParameterSpec("secp160r1"));
    private static final NamedEllipticCurve SECP160R2 = new NamedEllipticCurve(17, true, "ECDSA", ECNamedCurveTable.getParameterSpec("secp160r2"));
    private static final NamedEllipticCurve SECP192K1 = new NamedEllipticCurve(18, true, "ECDSA", ECNamedCurveTable.getParameterSpec("secp192k1"));
    private static final NamedEllipticCurve SECP192R1 = new NamedEllipticCurve(19, true, "ECDSA", ECNamedCurveTable.getParameterSpec("secp192r1"));
    private static final NamedEllipticCurve SECP224K1 = new NamedEllipticCurve(20, true, "ECDSA", ECNamedCurveTable.getParameterSpec("secp224k1"));
    private static final NamedEllipticCurve SECP224R1 = new NamedEllipticCurve(21, true, "ECDSA", ECNamedCurveTable.getParameterSpec("secp224r1"));
    private static final NamedEllipticCurve SECP256K1 = new NamedEllipticCurve(22, true, "ECDSA", ECNamedCurveTable.getParameterSpec("secp256k1"));
    private static final NamedEllipticCurve SECP256R1 = new NamedEllipticCurve(23, true, "ECDSA", ECNamedCurveTable.getParameterSpec("secp256r1"));
    private static final NamedEllipticCurve SECP384R1 = new NamedEllipticCurve(24, true, "ECDSA", ECNamedCurveTable.getParameterSpec("secp384r1"));
    private static final NamedEllipticCurve SECP521R1 = new NamedEllipticCurve(25, true, "ECDSA", ECNamedCurveTable.getParameterSpec("secp521r1"));
    private static final NamedEllipticCurve BRAINPOOLP256R1 = new NamedEllipticCurve(26, true, "ECDSA", ECNamedCurveTable.getParameterSpec("brainpoolp256r1"));
    private static final NamedEllipticCurve BRAINPOOLP384R1 = new NamedEllipticCurve(27, true, "ECDSA", ECNamedCurveTable.getParameterSpec("brainpoolp384r1"));
    private static final NamedEllipticCurve BRAINPOOLP512R1 = new NamedEllipticCurve(28, true, "ECDSA", ECNamedCurveTable.getParameterSpec("brainpoolp512r1"));
    private static final NamedEllipticCurve X25519 = new NamedEllipticCurve(29, true, "XDH", NamedParameterSpec.X25519);
    private static final NamedEllipticCurve X448 = new NamedEllipticCurve(30, true, "XDH", NamedParameterSpec.X448);
    private static final NamedEllipticCurve BRAINPOOLP256R1TLS13 = new NamedEllipticCurve(31, true, "ECDSA", ECNamedCurveTable.getParameterSpec("brainpoolp256r1"));
    private static final NamedEllipticCurve BRAINPOOLP384R1TLS13 = new NamedEllipticCurve(32, true, "ECDSA", ECNamedCurveTable.getParameterSpec("brainpoolp384r1"));
    private static final NamedEllipticCurve BRAINPOOLP512R1TLS13 = new NamedEllipticCurve(33, true, "ECDSA", ECNamedCurveTable.getParameterSpec("brainpoolp512r1"));
    private static final NamedEllipticCurve GC256A = new NamedEllipticCurve(34, true, "ECDSA", ECNamedCurveTable.getParameterSpec("gc256a"));
    private static final NamedEllipticCurve GC256B = new NamedEllipticCurve(35, true, "ECDSA", ECNamedCurveTable.getParameterSpec("gc256b"));
    private static final NamedEllipticCurve GC256C = new NamedEllipticCurve(36, true, "ECDSA", ECNamedCurveTable.getParameterSpec("gc256c"));
    private static final NamedEllipticCurve GC256D = new NamedEllipticCurve(37, true, "ECDSA", ECNamedCurveTable.getParameterSpec("gc256d"));
    private static final NamedEllipticCurve GC512A = new NamedEllipticCurve(38, true, "ECDSA", ECNamedCurveTable.getParameterSpec("gc512a"));
    private static final NamedEllipticCurve GC512B = new NamedEllipticCurve(39, true, "ECDSA", ECNamedCurveTable.getParameterSpec("gc512b"));
    private static final NamedEllipticCurve GC512C = new NamedEllipticCurve(40, false, "ECDSA", ECNamedCurveTable.getParameterSpec("gc512c"));
    private static final NamedEllipticCurve CURVESM2 = new NamedEllipticCurve(41, true, "XDH", NamedParameterSpec.X25519);
    private static final NamedEllipticCurve ML_KEM_512 = new NamedEllipticCurve(512, true, "ML-KEM", NamedParameterSpec.ML_KEM_512);
    private static final NamedEllipticCurve ML_KEM_768 = new NamedEllipticCurve(513, true, "ML-KEM", NamedParameterSpec.ML_KEM_768);
    private static final NamedEllipticCurve ML_KEM_1024 = new NamedEllipticCurve(514, true, "ML-KEM", NamedParameterSpec.ML_KEM_1024);
    private static final NamedEllipticCurve X25519MLKEM768 = new NamedEllipticCurve(4588, true, "XDH", NamedParameterSpec.X25519);
    private static final NamedEllipticCurve SECP256R1MLKEM768 = new NamedEllipticCurve(4587, true, "ECDSA", ECNamedCurveTable.getParameterSpec("secp256r1"));

    public static NamedEllipticCurve sect163k1() {
        return SECT163K1;
    }

    public static NamedEllipticCurve sect163r1() {
        return SECT163R1;
    }

    public static NamedEllipticCurve sect163r2() {
        return SECT163R2;
    }

    public static NamedEllipticCurve sect193r1() {
        return SECT193R1;
    }

    public static NamedEllipticCurve sect193r2() {
        return SECT193R2;
    }

    public static NamedEllipticCurve sect233k1() {
        return SECT233K1;
    }

    public static NamedEllipticCurve sect233r1() {
        return SECT233R1;
    }

    public static NamedEllipticCurve sect239k1() {
        return SECT239K1;
    }

    public static NamedEllipticCurve sect283k1() {
        return SECT283K1;
    }

    public static NamedEllipticCurve sect283r1() {
        return SECT283R1;
    }

    public static NamedEllipticCurve sect409k1() {
        return SECT409K1;
    }

    public static NamedEllipticCurve sect409r1() {
        return SECT409R1;
    }

    public static NamedEllipticCurve sect571k1() {
        return SECT571K1;
    }

    public static NamedEllipticCurve sect571r1() {
        return SECT571R1;
    }

    public static NamedEllipticCurve secp160k1() {
        return SECP160K1;
    }

    public static NamedEllipticCurve secp160r1() {
        return SECP160R1;
    }

    public static NamedEllipticCurve secp160r2() {
        return SECP160R2;
    }

    public static NamedEllipticCurve secp192k1() {
        return SECP192K1;
    }

    public static NamedEllipticCurve secp192r1() {
        return SECP192R1;
    }

    public static NamedEllipticCurve secp224k1() {
        return SECP224K1;
    }

    public static NamedEllipticCurve secp224r1() {
        return SECP224R1;
    }

    public static NamedEllipticCurve secp256k1() {
        return SECP256K1;
    }

    public static NamedEllipticCurve secp256r1() {
        return SECP256R1;
    }

    public static NamedEllipticCurve secp384r1() {
        return SECP384R1;
    }

    public static NamedEllipticCurve secp521r1() {
        return SECP521R1;
    }

    public static NamedEllipticCurve brainpoolp256r1() {
        return BRAINPOOLP256R1;
    }

    public static NamedEllipticCurve brainpoolp384r1() {
        return BRAINPOOLP384R1;
    }

    public static NamedEllipticCurve brainpoolp512r1() {
        return BRAINPOOLP512R1;
    }

    public static NamedEllipticCurve gc256a() {
        return GC256A;
    }

    public static NamedEllipticCurve gc256b() {
        return GC256B;
    }

    public static NamedEllipticCurve gc256c() {
        return GC256C;
    }

    public static NamedEllipticCurve gc256d() {
        return GC256D;
    }

    public static NamedEllipticCurve gc512a() {
        return GC512A;
    }

    public static NamedEllipticCurve gc512b() {
        return GC512B;
    }

    public static NamedEllipticCurve gc512c() {
        return GC512C;
    }

    public static NamedEllipticCurve x25519() {
        return X25519;
    }

    public static NamedEllipticCurve x448() {
        return X448;
    }

    public static NamedEllipticCurve mlKem512() {
        return ML_KEM_512;
    }

    public static NamedEllipticCurve mlKem768() {
        return ML_KEM_768;
    }

    public static NamedEllipticCurve mlKem1024() {
        return ML_KEM_1024;
    }

    public static NamedEllipticCurve x25519MlKem768() {
        return X25519MLKEM768;
    }

    public static NamedEllipticCurve secp256r1MlKem768() {
        return SECP256R1MLKEM768;
    }

    public static NamedEllipticCurve brainpoolp256r1Tls13() {
        return BRAINPOOLP256R1TLS13;
    }

    public static NamedEllipticCurve brainpoolp384r1Tls13() {
        return BRAINPOOLP384R1TLS13;
    }

    public static NamedEllipticCurve brainpoolp512r1Tls13() {
        return BRAINPOOLP512R1TLS13;
    }
    
    private final int id;
    private final boolean dtls;
    private final String algorithm;
    private final AlgorithmParameterSpec spec;

    private NamedEllipticCurve(int id, boolean dtls, String algorithm, AlgorithmParameterSpec spec) {
        this.id = id;
        this.dtls = dtls;
        this.algorithm = algorithm;
        this.spec = spec;
    }

    @Override
    public boolean accepts(int namedGroup) {
        return id == namedGroup;
    }

    @Override
    public Integer id() {
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

    public KeyPair generateKeyPair(TlsContext context) {
        try {
            var keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
            keyPairGenerator.initialize(spec);
            return keyPairGenerator.generateKeyPair();
        } catch (GeneralSecurityException exception) {
            throw new TlsAlert("Cannot generate EC keypair", exception);
        }
    }

    @Override
    public PublicKey parsePublicKey(byte[] key) {
        try {
            return switch (spec) {
                case ECNamedCurveParameterSpec bcSpec -> {
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
                    var keyFactory = KeyFactory.getInstance(algorithm);
                    var xecPublicKeySpec = new XECPublicKeySpec(namedParameterSpec, ECKeyUtils.fromUnsignedLittleEndianBytes(key));
                    yield keyFactory.generatePublic(xecPublicKeySpec);
                }
                default -> throw new TlsAlert("Unsupported spec");
            };
        } catch (NoSuchAlgorithmException exception) {
            throw new TlsAlert("Missing DH implementation", exception);
        } catch (GeneralSecurityException exception) {
            throw new TlsAlert("Cannot parse public DH key", exception);
        }
    }

    @Override
    public byte[] dumpPublicKey(PublicKey jcePublicKey) {
        return switch (jcePublicKey) {
            case XECPublicKey publicKey -> ECKeyUtils.toUnsignedLittleEndianBytes(publicKey.getU());
            case DHPublicKey publicKey -> ECKeyUtils.toUnsignedLittleEndianBytes(publicKey.getY());
            case ECPublicKey publicKey -> publicKey.getQ().getEncoded(false);
            default -> throw new TlsAlert("Unsupported key type");
        };
    }

    @Override
    public TlsSecret computeSharedSecret(TlsContext context) {
        var privateKey = context.localConnectionState()
                .ephemeralKeyPair()
                .orElseThrow(TlsAlert::noKeyPairSelected)
                .privateKey()
                .orElseThrow(() -> new TlsAlert("Missing local private key"));
        var keyExchangeType = context.getNegotiatedValue(TlsProperty.cipher())
                .orElseThrow(() -> TlsAlert.noNegotiatedProperty(TlsProperty.cipher()))
                .keyExchangeFactory()
                .type();
        var publicKey = switch (keyExchangeType) {
            case STATIC -> context.remoteConnectionState()
                    .flatMap(TlsConnection::staticCertificate)
                    .map(Certificate::getPublicKey)
                    .orElseThrow(() -> new TlsAlert("Missing remote public key for static pre master secret generation"));
            case EPHEMERAL -> context.remoteConnectionState()
                    .orElseThrow(TlsAlert::noRemoteConnectionState)
                    .ephemeralKeyPair()
                    .orElseThrow(() -> new TlsAlert("Missing remote public key for ephemeral pre master secret generation"))
                    .publicKey();
        };
        try {
            var keyAgreement = KeyAgreement.getInstance(algorithm);
            keyAgreement.init(privateKey, spec);
            keyAgreement.doPhase(publicKey, true);
            return TlsSecret.of(keyAgreement.generateSecret());
        }catch (GeneralSecurityException exception) {
            throw new TlsAlert("Cannot compute shared secret", exception);
        }
    }
}
