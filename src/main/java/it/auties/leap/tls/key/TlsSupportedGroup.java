package it.auties.leap.tls.key;

import it.auties.leap.tls.config.TlsIdentifiable;
import it.auties.leap.tls.config.TlsVersion;
import it.auties.leap.tls.exception.TlsException;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.spec.DHParameterSpec;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.spec.NamedParameterSpec;
import java.util.Objects;
import java.util.Optional;

// https://www.iana.org/assignments/tls-parameters/tls-parameters-8.csv
public sealed abstract class TlsSupportedGroup implements TlsIdentifiable.Int32<TlsSupportedGroup> {
    public static TlsSupportedGroup x25519() {
        return Xdh.X25519;
    }

    public static TlsSupportedGroup x448() {
        return Xdh.X448;
    }

    public static TlsSupportedGroup sect163k1() {
        return Ec.SECT163K1;
    }

    public static TlsSupportedGroup sect163r1() {
        return Ec.SECT163R1;
    }

    public static TlsSupportedGroup sect163r2() {
        return Ec.SECT163R2;
    }

    public static TlsSupportedGroup sect193r1() {
        return Ec.SECT193R1;
    }

    public static TlsSupportedGroup sect193r2() {
        return Ec.SECT193R2;
    }

    public static TlsSupportedGroup sect233k1() {
        return Ec.SECT233K1;
    }

    public static TlsSupportedGroup sect233r1() {
        return Ec.SECT233R1;
    }

    public static TlsSupportedGroup sect239k1() {
        return Ec.SECT239K1;
    }

    public static TlsSupportedGroup sect283k1() {
        return Ec.SECT283K1;
    }

    public static TlsSupportedGroup sect283r1() {
        return Ec.SECT283R1;
    }

    public static TlsSupportedGroup sect409k1() {
        return Ec.SECT409K1;
    }

    public static TlsSupportedGroup sect409r1() {
        return Ec.SECT409R1;
    }

    public static TlsSupportedGroup sect571k1() {
        return Ec.SECT571K1;
    }

    public static TlsSupportedGroup sect571r1() {
        return Ec.SECT571R1;
    }

    public static TlsSupportedGroup secp160k1() {
        return Ec.SECP160K1;
    }

    public static TlsSupportedGroup secp160r1() {
        return Ec.SECP160R1;
    }

    public static TlsSupportedGroup secp160r2() {
        return Ec.SECP160R2;
    }

    public static TlsSupportedGroup secp192k1() {
        return Ec.SECP192K1;
    }

    public static TlsSupportedGroup secp192r1() {
        return Ec.SECP192R1;
    }

    public static TlsSupportedGroup secp224k1() {
        return Ec.SECP224K1;
    }

    public static TlsSupportedGroup secp224r1() {
        return Ec.SECP224R1;
    }

    public static TlsSupportedGroup secp256k1() {
        return Ec.SECP256K1;
    }

    public static TlsSupportedGroup secp256r1() {
        return Ec.SECP256R1;
    }

    public static TlsSupportedGroup secp384r1() {
        return Ec.SECP384R1;
    }

    public static TlsSupportedGroup secp521r1() {
        return Ec.SECP521R1;
    }

    public static TlsSupportedGroup brainpoolp256r1() {
        return Ec.BRAINPOOLP256R1;
    }

    public static TlsSupportedGroup brainpoolp384r1() {
        return Ec.BRAINPOOLP384R1;
    }

    public static TlsSupportedGroup brainpoolp512r1() {
        return Ec.BRAINPOOLP512R1;
    }

    public static TlsSupportedGroup brainpoolp256r1Tls13() {
        return Ec.BRAINPOOLP256R1TLS13;
    }

    public static TlsSupportedGroup brainpoolp384r1Tls13() {
        return Ec.BRAINPOOLP384R1TLS13;
    }

    public static TlsSupportedGroup brainpoolp512r1Tls13() {
        return Ec.BRAINPOOLP512R1TLS13;
    }

    public static TlsSupportedGroup gc256a() {
        return Ec.GC256A;
    }

    public static TlsSupportedGroup gc256b() {
        return Ec.GC256B;
    }

    public static TlsSupportedGroup gc256c() {
        return Ec.GC256C;
    }

    public static TlsSupportedGroup gc256d() {
        return Ec.GC256D;
    }

    public static TlsSupportedGroup gc512a() {
        return Ec.GC512A;
    }

    public static TlsSupportedGroup gc512b() {
        return Ec.GC512B;
    }

    public static TlsSupportedGroup gc512c() {
        return Ec.GC512C;
    }

    public static TlsSupportedGroup ffdhe2048() {
        return Dhe.FFDHE2048;
    }

    public static TlsSupportedGroup ffdhe3072() {
        return Dhe.FFDHE3072;
    }

    public static TlsSupportedGroup ffdhe4096() {
        return Dhe.FFDHE4096;
    }

    public static TlsSupportedGroup ffdhe6144() {
        return Dhe.FFDHE6144;
    }

    public static TlsSupportedGroup ffdhe8192() {
        return Dhe.FFDHE8192;
    }

    public static TlsSupportedGroup curvesM2() {
        return Dhe.CURVESM2;
    }
    
    public static TlsSupportedGroup mlKem512() {
        return MlKem.ML_KEM_512;
    }

    public static TlsSupportedGroup mlKem768() {
        return MlKem.ML_KEM_768;
    }

    public static TlsSupportedGroup mlKem1024() {
        return MlKem.ML_KEM_1024;
    }

    public static TlsSupportedGroup x25519MlKem768() {
        return MlKem.X25519MLKEM768;
    }

    public static TlsSupportedGroup secp256r1MlKem768() {
        return MlKem.SECP256R1MLKEM768;
    }

    public static TlsSupportedGroup arbitraryExplicitChar2Curves() {
        return Arbitrary.ARBITRARY_EXPLICIT_CHAR2_CURVES;
    }

    public static TlsSupportedGroup arbitraryExplicitPrimeCurves() {
        return Arbitrary.ARBITRARY_EXPLICIT_PRIME_CURVES;
    }
    
    public static TlsSupportedGroup reservedForPrivateUse(int id, boolean dtls) {
        return reservedForPrivateUse(id, dtls, null);
    }

    public static TlsSupportedGroup reservedForPrivateUse(int id, boolean dtls, Reserved.Generator generator) {
        if(id < 0 || id > 65535) {
            throw new TlsException("Invalid reserved supported group: expected unsigned int16");
        }

        return new Reserved(id, dtls, Objects.requireNonNullElseGet(generator, Reserved.Generator::unsupported));
    }
    
    private final int id;
    private final boolean dtls;
    private TlsSupportedGroup(int value, boolean dtls) {
        this.id = value;
        this.dtls = dtls;
    }

    public abstract TlsKeyPair generateKeyPair(TlsVersion version);

    @Override
    public Integer id() {
        return id;
    }

    public boolean dtls() {
        return dtls;
    }

    public static final class Xdh extends TlsSupportedGroup {
        private static final TlsSupportedGroup X25519 = new Xdh(29, true, NamedParameterSpec.X25519);
        private static final TlsSupportedGroup X448 = new Xdh(30, true, NamedParameterSpec.X448);

        public static TlsSupportedGroup reservedForPrivateUse(int id, boolean dtls, NamedParameterSpec spec) {
            return new Xdh(id, dtls, spec);
        }

        private final NamedParameterSpec spec;
        private Xdh(int id, boolean dtls, NamedParameterSpec spec) {
            super(id, dtls);
            this.spec = spec;
        }

        @Override
        public TlsKeyPair generateKeyPair(TlsVersion version) {
            try {
                var keyPairGenerator = KeyPairGenerator.getInstance("XDH");
                keyPairGenerator.initialize(spec);
                return Optional.ofNullable(keyPairGenerator.genKeyPair());
            } catch (GeneralSecurityException exception) {
                return Optional.empty();
            }
        }
    }

    public static final class Ec extends TlsSupportedGroup {
        private static final TlsSupportedGroup SECT163K1 = new Ec(1, true, "sect163k1");
        private static final TlsSupportedGroup SECT163R1 = new Ec(2, true, "sect163r1");
        private static final TlsSupportedGroup SECT163R2 = new Ec(3, true, "sect163r2");
        private static final TlsSupportedGroup SECT193R1 = new Ec(4, true, "sect193r1");
        private static final TlsSupportedGroup SECT193R2 = new Ec(5, true, "sect193r2");
        private static final TlsSupportedGroup SECT233K1 = new Ec(6, true, "sect233k1");
        private static final TlsSupportedGroup SECT233R1 = new Ec(7, true, "sect233r1");
        private static final TlsSupportedGroup SECT239K1 = new Ec(8, true, "sect239k1");
        private static final TlsSupportedGroup SECT283K1 = new Ec(9, true, "sect283k1");
        private static final TlsSupportedGroup SECT283R1 = new Ec(10, true, "sect283r1");
        private static final TlsSupportedGroup SECT409K1 = new Ec(11, true, "sect409k1");
        private static final TlsSupportedGroup SECT409R1 = new Ec(12, true, "sect409r1");
        private static final TlsSupportedGroup SECT571K1 = new Ec(13, true, "sect571k1");
        private static final TlsSupportedGroup SECT571R1 = new Ec(14, true, "sect571r1");
        private static final TlsSupportedGroup SECP160K1 = new Ec(15, true, "secp160k1");
        private static final TlsSupportedGroup SECP160R1 = new Ec(16, true, "secp160r1");
        private static final TlsSupportedGroup SECP160R2 = new Ec(17, true, "secp160r2");
        private static final TlsSupportedGroup SECP192K1 = new Ec(18, true, "secp192k1");
        private static final TlsSupportedGroup SECP192R1 = new Ec(19, true, "secp192r1");
        private static final TlsSupportedGroup SECP224K1 = new Ec(20, true, "secp224k1");
        private static final TlsSupportedGroup SECP224R1 = new Ec(21, true, "secp224r1");
        private static final TlsSupportedGroup SECP256K1 = new Ec(22, true, "secp256k1");
        private static final TlsSupportedGroup SECP256R1 = new Ec(23, true, "secp256r1");
        private static final TlsSupportedGroup SECP384R1 = new Ec(24, true, "secp384r1");
        private static final TlsSupportedGroup SECP521R1 = new Ec(25, true, "secp521r1");
        private static final TlsSupportedGroup BRAINPOOLP256R1 = new Ec(26, true, "brainpoolp256r1");
        private static final TlsSupportedGroup BRAINPOOLP384R1 = new Ec(27, true, "brainpoolp384r1");
        private static final TlsSupportedGroup BRAINPOOLP512R1 = new Ec(28, true, "brainpoolp512r1");
        private static final TlsSupportedGroup BRAINPOOLP256R1TLS13 = new Ec(31, true, "brainpoolp256r1");
        private static final TlsSupportedGroup BRAINPOOLP384R1TLS13 = new Ec(32, true, "brainpoolp384r1");
        private static final TlsSupportedGroup BRAINPOOLP512R1TLS13 = new Ec(33, true, "brainpoolp512r1");
        private static final TlsSupportedGroup GC256A = new Ec(34, true, null);
        private static final TlsSupportedGroup GC256B = new Ec(35, true, null);
        private static final TlsSupportedGroup GC256C = new Ec(36, true, null);
        private static final TlsSupportedGroup GC256D = new Ec(37, true, null);
        private static final TlsSupportedGroup GC512A = new Ec(38, true, null);
        private static final TlsSupportedGroup GC512B = new Ec(39, true, null);
        private static final TlsSupportedGroup GC512C = new Ec(40, false, null);
        
        public static TlsSupportedGroup reservedForPrivateUse(int id, boolean dtls, String algorithmName) {
            return new Ec(id, dtls, algorithmName);
        }

        private final String name;
        private Ec(int id, boolean dtls, String name) {
            super(id, dtls);
            this.name = name;
        }

        static {
            Security.addProvider(new BouncyCastleProvider());
        }

        @Override
        public TlsKeyPair generateKeyPair(TlsVersion version) {
            try {
                var ecSpec = ECNamedCurveTable.getParameterSpec(name);
                var keyPairGenerator = KeyPairGenerator.getInstance("ECDSA", "BC");
                keyPairGenerator.initialize(ecSpec);
                return keyPairGenerator.generateKeyPair();
            } catch (GeneralSecurityException exception) {
                return Optional.empty();
            }
        }
    }

    public static final class Dhe extends TlsSupportedGroup {
        private static final BigInteger P2048 = new BigInteger("FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF97D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FBB96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F619172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA886B423861285C97FFFFFFFFFFFFFFFF", 16);
        private static final BigInteger P3072 = new BigInteger("FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF97D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FBB96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F619172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA886B4238611FCFDCDE355B3B6519035BBC34F4DEF99C023861B46FC9D6E6C9077AD91D2691F7F7EE598CB0FAC186D91CAEFE130985139270B4130C93BC437944F4FD4452E2D74DD364F2E21E71F54BFF5CAE82AB9C9DF69EE86D2BC522363A0DABC521979B0DEADA1DBF9A42D5C4484E0ABCD06BFA53DDEF3C1B20EE3FD59D7C25E41D2B66C62E37FFFFFFFFFFFFFFFF", 16);
        private static final BigInteger P4096 = new BigInteger("FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF97D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FBB96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F619172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA886B4238611FCFDCDE355B3B6519035BBC34F4DEF99C023861B46FC9D6E6C9077AD91D2691F7F7EE598CB0FAC186D91CAEFE130985139270B4130C93BC437944F4FD4452E2D74DD364F2E21E71F54BFF5CAE82AB9C9DF69EE86D2BC522363A0DABC521979B0DEADA1DBF9A42D5C4484E0ABCD06BFA53DDEF3C1B20EE3FD59D7C25E41D2B669E1EF16E6F52C3164DF4FB7930E9E4E58857B6AC7D5F42D69F6D187763CF1D5503400487F55BA57E31CC7A7135C886EFB4318AED6A1E012D9E6832A907600A918130C46DC778F971AD0038092999A333CB8B7A1A1DB93D7140003C2A4ECEA9F98D0ACC0A8291CDCEC97DCF8EC9B55A7F88A46B4DB5A851F44182E1C68A007E5E655F6AFFFFFFFFFFFFFFFF", 16);
        private static final BigInteger P6144 = new BigInteger("FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF97D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FBB96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F619172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA886B4238611FCFDCDE355B3B6519035BBC34F4DEF99C023861B46FC9D6E6C9077AD91D2691F7F7EE598CB0FAC186D91CAEFE130985139270B4130C93BC437944F4FD4452E2D74DD364F2E21E71F54BFF5CAE82AB9C9DF69EE86D2BC522363A0DABC521979B0DEADA1DBF9A42D5C4484E0ABCD06BFA53DDEF3C1B20EE3FD59D7C25E41D2B669E1EF16E6F52C3164DF4FB7930E9E4E58857B6AC7D5F42D69F6D187763CF1D5503400487F55BA57E31CC7A7135C886EFB4318AED6A1E012D9E6832A907600A918130C46DC778F971AD0038092999A333CB8B7A1A1DB93D7140003C2A4ECEA9F98D0ACC0A8291CDCEC97DCF8EC9B55A7F88A46B4DB5A851F44182E1C68A007E5E0DD9020BFD64B645036C7A4E677D2C38532A3A23BA4442CAF53EA63BB454329B7624C8917BDD64B1C0FD4CB38E8C334C701C3ACDAD0657FCCFEC719B1F5C3E4E46041F388147FB4CFDB477A52471F7A9A96910B855322EDB6340D8A00EF092350511E30ABEC1FFF9E3A26E7FB29F8C183023C3587E38DA0077D9B4763E4E4B94B2BBC194C6651E77CAF992EEAAC0232A281BF6B3A739C1226116820AE8DB5847A67CBEF9C9091B462D538CD72B03746AE77F5E62292C311562A846505DC82DB854338AE49F5235C95B91178CCF2DD5CACEF403EC9D1810C6272B045B3B71F9DC6B80D63FDD4A8E9ADB1E6962A69526D43161C1A41D570D7938DAD4A40E329CD0E40E65FFFFFFFFFFFFFFFF", 16);
        private static final BigInteger P8192 = new BigInteger("FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF97D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FBB96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F619172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA886B4238611FCFDCDE355B3B6519035BBC34F4DEF99C023861B46FC9D6E6C9077AD91D2691F7F7EE598CB0FAC186D91CAEFE130985139270B4130C93BC437944F4FD4452E2D74DD364F2E21E71F54BFF5CAE82AB9C9DF69EE86D2BC522363A0DABC521979B0DEADA1DBF9A42D5C4484E0ABCD06BFA53DDEF3C1B20EE3FD59D7C25E41D2B669E1EF16E6F52C3164DF4FB7930E9E4E58857B6AC7D5F42D69F6D187763CF1D5503400487F55BA57E31CC7A7135C886EFB4318AED6A1E012D9E6832A907600A918130C46DC778F971AD0038092999A333CB8B7A1A1DB93D7140003C2A4ECEA9F98D0ACC0A8291CDCEC97DCF8EC9B55A7F88A46B4DB5A851F44182E1C68A007E5E0DD9020BFD64B645036C7A4E677D2C38532A3A23BA4442CAF53EA63BB454329B7624C8917BDD64B1C0FD4CB38E8C334C701C3ACDAD0657FCCFEC719B1F5C3E4E46041F388147FB4CFDB477A52471F7A9A96910B855322EDB6340D8A00EF092350511E30ABEC1FFF9E3A26E7FB29F8C183023C3587E38DA0077D9B4763E4E4B94B2BBC194C6651E77CAF992EEAAC0232A281BF6B3A739C1226116820AE8DB5847A67CBEF9C9091B462D538CD72B03746AE77F5E62292C311562A846505DC82DB854338AE49F5235C95B91178CCF2DD5CACEF403EC9D1810C6272B045B3B71F9DC6B80D63FDD4A8E9ADB1E6962A69526D43161C1A41D570D7938DAD4A40E329CCFF46AAA36AD004CF600C8381E425A31D951AE64FDB23FCEC9509D43687FEB69EDD1CC5E0B8CC3BDF64B10EF86B63142A3AB8829555B2F747C932665CB2C0F1CC01BD70229388839D2AF05E454504AC78B7582822846C0BA35C35F5C59160CC046FD8251541FC68C9C86B022BB7099876A460E7451A8A93109703FEE1C217E6C3826E52C51AA691E0E423CFC99E9E31650C1217B624816CDAD9A95F9D5B8019488D9C0A0A1FE3075A577E23183F81D4A3F2FA4571EFC8CE0BA8A4FE8B6855DFE72B0A66EDED2FBABFBE58A30FAFABE1C5D71A87E2F741EF8C1FE86FEA6BBFDE530677F0D97D11D49F7A8443D0822E506A9F4614E011E2A94838FF88CD68C8BB7C5C6424CFFFFFFFFFFFFFFFF", 16);

        private static final TlsSupportedGroup FFDHE2048 = new Dhe(256, true, new DHParameterSpec(P2048, BigInteger.TWO));
        private static final TlsSupportedGroup FFDHE3072 = new Dhe(257, true, new DHParameterSpec(P3072, BigInteger.TWO));
        private static final TlsSupportedGroup FFDHE4096 = new Dhe(258, true, new DHParameterSpec(P4096, BigInteger.TWO));
        private static final TlsSupportedGroup FFDHE6144 = new Dhe(259, true, new DHParameterSpec(P6144, BigInteger.TWO));
        private static final TlsSupportedGroup FFDHE8192 = new Dhe(260, true, new DHParameterSpec(P8192, BigInteger.TWO));
        private static final TlsSupportedGroup CURVESM2 = new Dhe(41, true, null);

        public static TlsSupportedGroup reservedForPrivateUse(int id, boolean dtls, DHParameterSpec spec) {
            return new Dhe(id, dtls, spec);
        }

        private final DHParameterSpec spec;
        private Dhe(int id, boolean dtls, DHParameterSpec spec) {
            super(id, dtls);
            this.spec = spec;
        }

        @Override
        public TlsKeyPair generateKeyPair(TlsVersion version) {
            try {
                var keyPairGenerator = KeyPairGenerator.getInstance("DH");
                keyPairGenerator.initialize(spec);
                return keyPairGenerator.generateKeyPair();
            } catch (GeneralSecurityException exception) {
                return Optional.empty();
            }
        }
    }

    public static final class MlKem extends TlsSupportedGroup {
        private static final TlsSupportedGroup ML_KEM_512 = new MlKem(512, true, NamedParameterSpec.ML_KEM_512);
        private static final TlsSupportedGroup ML_KEM_768 = new MlKem(513, true, NamedParameterSpec.ML_KEM_768);
        private static final TlsSupportedGroup ML_KEM_1024 = new MlKem(514, true, NamedParameterSpec.ML_KEM_1024);
        private static final TlsSupportedGroup X25519MLKEM768 = new MlKem(4588, true, null);
        private static final TlsSupportedGroup SECP256R1MLKEM768 = new MlKem(4587, true, null);
        
        public static TlsSupportedGroup reservedForPrivateUse(int id, boolean dtls, NamedParameterSpec spec) {
            return new MlKem(id, dtls, spec);
        }

        private final NamedParameterSpec spec;
        private MlKem(int id, boolean dtls, NamedParameterSpec spec) {
            super(id, dtls);
            this.spec = spec;
        }

        @Override
        public TlsKeyPair generateKeyPair(TlsVersion version) {
            try {
                var keyPairGenerator = KeyPairGenerator.getInstance("ML-KEM");
                keyPairGenerator.initialize(spec);
                return keyPairGenerator.generateKeyPair();
            } catch (GeneralSecurityException exception) {
                return Optional.empty();
            }
        }
    }

    public static final class Arbitrary extends TlsSupportedGroup {
        private static final TlsSupportedGroup ARBITRARY_EXPLICIT_PRIME_CURVES = new Arbitrary(65281, true);
        private static final TlsSupportedGroup ARBITRARY_EXPLICIT_CHAR2_CURVES = new Arbitrary(65282, true);
        
        public static TlsSupportedGroup reservedForPrivateUse(int id, boolean dtls) {
            return new Arbitrary(id, dtls);
        }

        private Arbitrary(int id, boolean dtls) {
            super(id, dtls);
        }

        @Override
        public TlsKeyPair generateKeyPair(TlsVersion version) {
            return Optional.empty();
        }
    }

    public static final class Reserved extends TlsSupportedGroup {
        private final Generator generator;
        private Reserved(int value, boolean dtls, Generator generator) {
            super(value, dtls);
            this.generator = generator;
        }

        @Override
        public TlsKeyPair generateKeyPair(TlsVersion version) {
            return generator.generate(version);
        }

        @FunctionalInterface
        public interface Generator {
            TlsKeyPair generate(TlsVersion version);

            static Generator unsupported() {
                final class Unsupported implements Generator {
                    private static final Unsupported INSTANCE = new Unsupported();

                    private Unsupported() {

                    }

                    @Override
                    public TlsKeyPair generate(TlsVersion version) {
                        return Optional.empty();
                    }
                }

                return Unsupported.INSTANCE;
            }
        }
    }
}
