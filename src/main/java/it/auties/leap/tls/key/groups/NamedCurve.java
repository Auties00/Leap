package it.auties.leap.tls.key.groups;

import it.auties.leap.tls.TlsContext;
import it.auties.leap.tls.cipher.exchange.client.DHClientKeyExchange;
import it.auties.leap.tls.cipher.exchange.client.ECDHClientKeyExchange;
import it.auties.leap.tls.cipher.exchange.server.DHServerKeyExchange;
import it.auties.leap.tls.cipher.exchange.server.ECDHServerKeyExchange;
import it.auties.leap.tls.ec.TlsECParameters;
import it.auties.leap.tls.ec.TlsECParametersDeserializer;
import it.auties.leap.tls.ec.implementation.NamedCurveParameters;
import it.auties.leap.tls.exception.TlsException;
import it.auties.leap.tls.key.TlsSupportedGroup;
import it.auties.leap.tls.util.KeyUtils;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;

import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.XECPublicKey;
import java.security.spec.*;
import java.util.Arrays;
import java.util.Optional;

public final class NamedCurve implements TlsSupportedGroup {
    private static final BigInteger P2048 = new BigInteger("FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF97D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FBB96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F619172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA886B423861285C97FFFFFFFFFFFFFFFF", 16);
    private static final BigInteger P3072 = new BigInteger("FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF97D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FBB96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F619172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA886B4238611FCFDCDE355B3B6519035BBC34F4DEF99C023861B46FC9D6E6C9077AD91D2691F7F7EE598CB0FAC186D91CAEFE130985139270B4130C93BC437944F4FD4452E2D74DD364F2E21E71F54BFF5CAE82AB9C9DF69EE86D2BC522363A0DABC521979B0DEADA1DBF9A42D5C4484E0ABCD06BFA53DDEF3C1B20EE3FD59D7C25E41D2B66C62E37FFFFFFFFFFFFFFFF", 16);
    private static final BigInteger P4096 = new BigInteger("FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF97D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FBB96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F619172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA886B4238611FCFDCDE355B3B6519035BBC34F4DEF99C023861B46FC9D6E6C9077AD91D2691F7F7EE598CB0FAC186D91CAEFE130985139270B4130C93BC437944F4FD4452E2D74DD364F2E21E71F54BFF5CAE82AB9C9DF69EE86D2BC522363A0DABC521979B0DEADA1DBF9A42D5C4484E0ABCD06BFA53DDEF3C1B20EE3FD59D7C25E41D2B669E1EF16E6F52C3164DF4FB7930E9E4E58857B6AC7D5F42D69F6D187763CF1D5503400487F55BA57E31CC7A7135C886EFB4318AED6A1E012D9E6832A907600A918130C46DC778F971AD0038092999A333CB8B7A1A1DB93D7140003C2A4ECEA9F98D0ACC0A8291CDCEC97DCF8EC9B55A7F88A46B4DB5A851F44182E1C68A007E5E655F6AFFFFFFFFFFFFFFFF", 16);
    private static final BigInteger P6144 = new BigInteger("FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF97D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FBB96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F619172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA886B4238611FCFDCDE355B3B6519035BBC34F4DEF99C023861B46FC9D6E6C9077AD91D2691F7F7EE598CB0FAC186D91CAEFE130985139270B4130C93BC437944F4FD4452E2D74DD364F2E21E71F54BFF5CAE82AB9C9DF69EE86D2BC522363A0DABC521979B0DEADA1DBF9A42D5C4484E0ABCD06BFA53DDEF3C1B20EE3FD59D7C25E41D2B669E1EF16E6F52C3164DF4FB7930E9E4E58857B6AC7D5F42D69F6D187763CF1D5503400487F55BA57E31CC7A7135C886EFB4318AED6A1E012D9E6832A907600A918130C46DC778F971AD0038092999A333CB8B7A1A1DB93D7140003C2A4ECEA9F98D0ACC0A8291CDCEC97DCF8EC9B55A7F88A46B4DB5A851F44182E1C68A007E5E0DD9020BFD64B645036C7A4E677D2C38532A3A23BA4442CAF53EA63BB454329B7624C8917BDD64B1C0FD4CB38E8C334C701C3ACDAD0657FCCFEC719B1F5C3E4E46041F388147FB4CFDB477A52471F7A9A96910B855322EDB6340D8A00EF092350511E30ABEC1FFF9E3A26E7FB29F8C183023C3587E38DA0077D9B4763E4E4B94B2BBC194C6651E77CAF992EEAAC0232A281BF6B3A739C1226116820AE8DB5847A67CBEF9C9091B462D538CD72B03746AE77F5E62292C311562A846505DC82DB854338AE49F5235C95B91178CCF2DD5CACEF403EC9D1810C6272B045B3B71F9DC6B80D63FDD4A8E9ADB1E6962A69526D43161C1A41D570D7938DAD4A40E329CD0E40E65FFFFFFFFFFFFFFFF", 16);
    private static final BigInteger P8192 = new BigInteger("FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF97D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FBB96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F619172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA886B4238611FCFDCDE355B3B6519035BBC34F4DEF99C023861B46FC9D6E6C9077AD91D2691F7F7EE598CB0FAC186D91CAEFE130985139270B4130C93BC437944F4FD4452E2D74DD364F2E21E71F54BFF5CAE82AB9C9DF69EE86D2BC522363A0DABC521979B0DEADA1DBF9A42D5C4484E0ABCD06BFA53DDEF3C1B20EE3FD59D7C25E41D2B669E1EF16E6F52C3164DF4FB7930E9E4E58857B6AC7D5F42D69F6D187763CF1D5503400487F55BA57E31CC7A7135C886EFB4318AED6A1E012D9E6832A907600A918130C46DC778F971AD0038092999A333CB8B7A1A1DB93D7140003C2A4ECEA9F98D0ACC0A8291CDCEC97DCF8EC9B55A7F88A46B4DB5A851F44182E1C68A007E5E0DD9020BFD64B645036C7A4E677D2C38532A3A23BA4442CAF53EA63BB454329B7624C8917BDD64B1C0FD4CB38E8C334C701C3ACDAD0657FCCFEC719B1F5C3E4E46041F388147FB4CFDB477A52471F7A9A96910B855322EDB6340D8A00EF092350511E30ABEC1FFF9E3A26E7FB29F8C183023C3587E38DA0077D9B4763E4E4B94B2BBC194C6651E77CAF992EEAAC0232A281BF6B3A739C1226116820AE8DB5847A67CBEF9C9091B462D538CD72B03746AE77F5E62292C311562A846505DC82DB854338AE49F5235C95B91178CCF2DD5CACEF403EC9D1810C6272B045B3B71F9DC6B80D63FDD4A8E9ADB1E6962A69526D43161C1A41D570D7938DAD4A40E329CCFF46AAA36AD004CF600C8381E425A31D951AE64FDB23FCEC9509D43687FEB69EDD1CC5E0B8CC3BDF64B10EF86B63142A3AB8829555B2F747C932665CB2C0F1CC01BD70229388839D2AF05E454504AC78B7582822846C0BA35C35F5C59160CC046FD8251541FC68C9C86B022BB7099876A460E7451A8A93109703FEE1C217E6C3826E52C51AA691E0E423CFC99E9E31650C1217B624816CDAD9A95F9D5B8019488D9C0A0A1FE3075A577E23183F81D4A3F2FA4571EFC8CE0BA8A4FE8B6855DFE72B0A66EDED2FBABFBE58A30FAFABE1C5D71A87E2F741EF8C1FE86FEA6BBFDE530677F0D97D11D49F7A8443D0822E506A9F4614E011E2A94838FF88CD68C8BB7C5C6424CFFFFFFFFFFFFFFFF", 16);
    
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
    private static final NamedCurve FFDHE2048 = new NamedCurve(256, true, "DH", new DHParameterSpec(P2048, BigInteger.TWO));
    private static final NamedCurve FFDHE3072 = new NamedCurve(257, true, "DH", new DHParameterSpec(P3072, BigInteger.TWO));
    private static final NamedCurve FFDHE4096 = new NamedCurve(258, true, "DH", new DHParameterSpec(P4096, BigInteger.TWO));
    private static final NamedCurve FFDHE6144 = new NamedCurve(259, true, "DH", new DHParameterSpec(P6144, BigInteger.TWO));
    private static final NamedCurve FFDHE8192 = new NamedCurve(260, true, "DH", new DHParameterSpec(P8192, BigInteger.TWO));
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

    public static NamedCurve ffdhe2048() {
        return FFDHE2048;
    }

    public static NamedCurve ffdhe3072() {
        return FFDHE3072;
    }

    public static NamedCurve ffdhe4096() {
        return FFDHE4096;
    }

    public static NamedCurve ffdhe6144() {
        return FFDHE6144;
    }

    public static NamedCurve ffdhe8192() {
        return FFDHE8192;
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
    public Optional<TlsECParameters> toEllipticCurveParameters() {
        return Optional.of(new NamedCurveParameters(id));
    }

    @Override
    public Optional<TlsECParametersDeserializer> ellipticCurveParametersDeserializer() {
        return Optional.of(TlsECParametersDeserializer.namedCurve());
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

    @Override
    public PublicKey parseRemotePublicKey(TlsContext context) {
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
                case DHParameterSpec _ -> {
                    var key = switch (mode) {
                        case CLIENT -> {
                            if(!(remoteKeyExchange instanceof DHServerKeyExchange serverKeyExchange)) {
                                throw new TlsException("Unsupported key type");
                            }
                            yield serverKeyExchange.y();
                        }
                        case SERVER -> {
                            if(!(remoteKeyExchange instanceof DHClientKeyExchange clientKeyExchange)) {
                                throw new TlsException("Unsupported key type");
                            }
                            yield clientKeyExchange.y();
                        }
                    };
                    var serverKeyExchange = switch (mode) {
                        case CLIENT  -> (DHServerKeyExchange) remoteKeyExchange;
                        case SERVER -> context.localKeyExchange()
                                .map(entry -> entry instanceof DHServerKeyExchange exchange ? exchange : null)
                                .orElseThrow(() -> new TlsException("Missing local key exchange"));
                    };
                    var keyFactory = KeyFactory.getInstance("DH");
                    var dhPubKeySpecs = new DHPublicKeySpec(
                            KeyUtils.fromUnsignedLittleEndianBytes(key),
                            KeyUtils.fromUnsignedLittleEndianBytes(serverKeyExchange.p()),
                            KeyUtils.fromUnsignedLittleEndianBytes(serverKeyExchange.g())
                    );
                    yield keyFactory.generatePublic(dhPubKeySpecs);
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
            System.out.printf(
                    """
                            Local public key: %s
                            Remote public key: %s
                            %n""", Arrays.toString(KeyUtils.toUnsignedLittleEndianBytes(((XECPublicKey) context.localKeyPair().get().getPublic()).getU())),
                    Arrays.toString(KeyUtils.toUnsignedLittleEndianBytes(((XECPublicKey) publicKey).getU()))
            );
            var keyAgreement = KeyAgreement.getInstance(algorithm);
            keyAgreement.init(privateKey, spec);
            keyAgreement.doPhase(publicKey, true);
            return keyAgreement.generateSecret();
        }catch (GeneralSecurityException exception) {
            throw new TlsException("Cannot compute DH shared secret", exception);
        }
    }
}
