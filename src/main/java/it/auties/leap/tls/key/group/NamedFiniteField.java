package it.auties.leap.tls.key.group;

import it.auties.leap.tls.TlsContext;
import it.auties.leap.tls.cipher.exchange.TlsServerKeyExchange;
import it.auties.leap.tls.cipher.exchange.client.DHClientKeyExchange;
import it.auties.leap.tls.cipher.exchange.server.DHServerKeyExchange;
import it.auties.leap.tls.exception.TlsException;
import it.auties.leap.tls.key.TlsSupportedFiniteField;

import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.util.Arrays;

public final class NamedFiniteField implements TlsSupportedFiniteField {
    private static final BigInteger P2048 = new BigInteger("FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF97D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FBB96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F619172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA886B423861285C97FFFFFFFFFFFFFFFF", 16);
    private static final BigInteger P3072 = new BigInteger("FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF97D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FBB96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F619172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA886B4238611FCFDCDE355B3B6519035BBC34F4DEF99C023861B46FC9D6E6C9077AD91D2691F7F7EE598CB0FAC186D91CAEFE130985139270B4130C93BC437944F4FD4452E2D74DD364F2E21E71F54BFF5CAE82AB9C9DF69EE86D2BC522363A0DABC521979B0DEADA1DBF9A42D5C4484E0ABCD06BFA53DDEF3C1B20EE3FD59D7C25E41D2B66C62E37FFFFFFFFFFFFFFFF", 16);
    private static final BigInteger P4096 = new BigInteger("FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF97D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FBB96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F619172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA886B4238611FCFDCDE355B3B6519035BBC34F4DEF99C023861B46FC9D6E6C9077AD91D2691F7F7EE598CB0FAC186D91CAEFE130985139270B4130C93BC437944F4FD4452E2D74DD364F2E21E71F54BFF5CAE82AB9C9DF69EE86D2BC522363A0DABC521979B0DEADA1DBF9A42D5C4484E0ABCD06BFA53DDEF3C1B20EE3FD59D7C25E41D2B669E1EF16E6F52C3164DF4FB7930E9E4E58857B6AC7D5F42D69F6D187763CF1D5503400487F55BA57E31CC7A7135C886EFB4318AED6A1E012D9E6832A907600A918130C46DC778F971AD0038092999A333CB8B7A1A1DB93D7140003C2A4ECEA9F98D0ACC0A8291CDCEC97DCF8EC9B55A7F88A46B4DB5A851F44182E1C68A007E5E655F6AFFFFFFFFFFFFFFFF", 16);
    private static final BigInteger P6144 = new BigInteger("FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF97D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FBB96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F619172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA886B4238611FCFDCDE355B3B6519035BBC34F4DEF99C023861B46FC9D6E6C9077AD91D2691F7F7EE598CB0FAC186D91CAEFE130985139270B4130C93BC437944F4FD4452E2D74DD364F2E21E71F54BFF5CAE82AB9C9DF69EE86D2BC522363A0DABC521979B0DEADA1DBF9A42D5C4484E0ABCD06BFA53DDEF3C1B20EE3FD59D7C25E41D2B669E1EF16E6F52C3164DF4FB7930E9E4E58857B6AC7D5F42D69F6D187763CF1D5503400487F55BA57E31CC7A7135C886EFB4318AED6A1E012D9E6832A907600A918130C46DC778F971AD0038092999A333CB8B7A1A1DB93D7140003C2A4ECEA9F98D0ACC0A8291CDCEC97DCF8EC9B55A7F88A46B4DB5A851F44182E1C68A007E5E0DD9020BFD64B645036C7A4E677D2C38532A3A23BA4442CAF53EA63BB454329B7624C8917BDD64B1C0FD4CB38E8C334C701C3ACDAD0657FCCFEC719B1F5C3E4E46041F388147FB4CFDB477A52471F7A9A96910B855322EDB6340D8A00EF092350511E30ABEC1FFF9E3A26E7FB29F8C183023C3587E38DA0077D9B4763E4E4B94B2BBC194C6651E77CAF992EEAAC0232A281BF6B3A739C1226116820AE8DB5847A67CBEF9C9091B462D538CD72B03746AE77F5E62292C311562A846505DC82DB854338AE49F5235C95B91178CCF2DD5CACEF403EC9D1810C6272B045B3B71F9DC6B80D63FDD4A8E9ADB1E6962A69526D43161C1A41D570D7938DAD4A40E329CD0E40E65FFFFFFFFFFFFFFFF", 16);
    private static final BigInteger P8192 = new BigInteger("FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF97D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FBB96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F619172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA886B4238611FCFDCDE355B3B6519035BBC34F4DEF99C023861B46FC9D6E6C9077AD91D2691F7F7EE598CB0FAC186D91CAEFE130985139270B4130C93BC437944F4FD4452E2D74DD364F2E21E71F54BFF5CAE82AB9C9DF69EE86D2BC522363A0DABC521979B0DEADA1DBF9A42D5C4484E0ABCD06BFA53DDEF3C1B20EE3FD59D7C25E41D2B669E1EF16E6F52C3164DF4FB7930E9E4E58857B6AC7D5F42D69F6D187763CF1D5503400487F55BA57E31CC7A7135C886EFB4318AED6A1E012D9E6832A907600A918130C46DC778F971AD0038092999A333CB8B7A1A1DB93D7140003C2A4ECEA9F98D0ACC0A8291CDCEC97DCF8EC9B55A7F88A46B4DB5A851F44182E1C68A007E5E0DD9020BFD64B645036C7A4E677D2C38532A3A23BA4442CAF53EA63BB454329B7624C8917BDD64B1C0FD4CB38E8C334C701C3ACDAD0657FCCFEC719B1F5C3E4E46041F388147FB4CFDB477A52471F7A9A96910B855322EDB6340D8A00EF092350511E30ABEC1FFF9E3A26E7FB29F8C183023C3587E38DA0077D9B4763E4E4B94B2BBC194C6651E77CAF992EEAAC0232A281BF6B3A739C1226116820AE8DB5847A67CBEF9C9091B462D538CD72B03746AE77F5E62292C311562A846505DC82DB854338AE49F5235C95B91178CCF2DD5CACEF403EC9D1810C6272B045B3B71F9DC6B80D63FDD4A8E9ADB1E6962A69526D43161C1A41D570D7938DAD4A40E329CCFF46AAA36AD004CF600C8381E425A31D951AE64FDB23FCEC9509D43687FEB69EDD1CC5E0B8CC3BDF64B10EF86B63142A3AB8829555B2F747C932665CB2C0F1CC01BD70229388839D2AF05E454504AC78B7582822846C0BA35C35F5C59160CC046FD8251541FC68C9C86B022BB7099876A460E7451A8A93109703FEE1C217E6C3826E52C51AA691E0E423CFC99E9E31650C1217B624816CDAD9A95F9D5B8019488D9C0A0A1FE3075A577E23183F81D4A3F2FA4571EFC8CE0BA8A4FE8B6855DFE72B0A66EDED2FBABFBE58A30FAFABE1C5D71A87E2F741EF8C1FE86FEA6BBFDE530677F0D97D11D49F7A8443D0822E506A9F4614E011E2A94838FF88CD68C8BB7C5C6424CFFFFFFFFFFFFFFFF", 16);

    private static final NamedFiniteField FFDHE2048 = new NamedFiniteField(256, true, new DHParameterSpec(P2048, BigInteger.TWO));
    private static final NamedFiniteField FFDHE3072 = new NamedFiniteField(257, true, new DHParameterSpec(P3072, BigInteger.TWO));
    private static final NamedFiniteField FFDHE4096 = new NamedFiniteField(258, true, new DHParameterSpec(P4096, BigInteger.TWO));
    private static final NamedFiniteField FFDHE6144 = new NamedFiniteField(259, true, new DHParameterSpec(P6144, BigInteger.TWO));
    private static final NamedFiniteField FFDHE8192 = new NamedFiniteField(260, true, new DHParameterSpec(P8192, BigInteger.TWO));

    public static NamedFiniteField ffdhe2048() {
        return FFDHE2048;
    }

    public static NamedFiniteField ffdhe3072() {
        return FFDHE3072;
    }

    public static NamedFiniteField ffdhe4096() {
        return FFDHE4096;
    }

    public static NamedFiniteField ffdhe6144() {
        return FFDHE6144;
    }

    public static NamedFiniteField ffdhe8192() {
        return FFDHE8192;
    }
    
    private final int id;
    private final boolean dtls;
    private final DHParameterSpec spec;

    private NamedFiniteField(int id, boolean dtls, DHParameterSpec spec) {
        this.id = id;
        this.dtls = dtls;
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

    public KeyPair generateLocalKeyPair(TlsContext context) {
        try {
            var keyPairGenerator = KeyPairGenerator.getInstance("DH");
            keyPairGenerator.initialize(spec);
            return keyPairGenerator.generateKeyPair();
        } catch (GeneralSecurityException exception) {
            throw new TlsException("Cannot generate EC keypair", exception);
        }
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
            var keyAgreement = KeyAgreement.getInstance("DH");
            keyAgreement.init(privateKey, spec);
            keyAgreement.doPhase(publicKey, true);
            var result = keyAgreement.generateSecret();
            System.out.println("Remote public key: " + Arrays.toString(((DHPublicKey) publicKey).getY().toByteArray()));
            System.out.println("Pre master secret: " + Arrays.toString(result));
            return result;
        }catch (GeneralSecurityException exception) {
            throw new TlsException("Cannot compute shared secret", exception);
        }
    }

    private PublicKey parseRemotePublicKey(TlsContext context) {
        var mode = context.selectedMode()
                .orElseThrow(() -> new TlsException("No mode was selected"));
        var remoteKeyExchange = context.remoteKeyExchange()
                .orElseThrow(() -> new TlsException("Missing remote key exchange"));
        return switch (mode) {
            case CLIENT -> {
                if(!(remoteKeyExchange instanceof DHServerKeyExchange serverKeyExchange)) {
                    throw new TlsException("Unsupported key type");
                }
                yield serverKeyExchange.getOrParsePublicKey();
            }
            case SERVER -> {
                if(!(remoteKeyExchange instanceof DHClientKeyExchange clientKeyExchange)) {
                    throw new TlsException("Unsupported key type");
                }
                var localPublicKey = context.localKeyPair()
                        .orElseThrow(() -> new TlsException("Missing local key pair"))
                        .getPublic();
                if(!(localPublicKey instanceof DHPublicKey dhPublicKey)) {
                    throw new TlsException("Unsupported key type");
                }
                yield clientKeyExchange.getOrParsePublicKey(dhPublicKey.getParams().getP(), dhPublicKey.getParams().getG());
            }
        };
    }

    @Override
    public boolean accepts(TlsServerKeyExchange exchange) {
        if(!(exchange instanceof DHServerKeyExchange serverKeyExchange)) {
            return false;
        }

        var params = serverKeyExchange.getOrParsePublicKey()
                .getParams();
        return params.getG().equals(spec.getG())
                && params.getP().equals(spec.getP());
    }
}
