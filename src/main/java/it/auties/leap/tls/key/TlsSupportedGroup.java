package it.auties.leap.tls.key;

import it.auties.leap.tls.ec.TlsECParameters;
import it.auties.leap.tls.ec.TlsECParametersDecoder;
import it.auties.leap.tls.exception.TlsException;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.util.Objects;

// Includes ECCurveType
// https://www.iana.org/assignments/tls-parameters/tls-parameters-8.csv
public sealed interface TlsSupportedGroup extends TlsKeyPairGenerator, TlsECParametersDecoder {
    static TlsSupportedGroup x25519() {
        return NamedCurve.X25519;
    }

    static TlsSupportedGroup x448() {
        return NamedCurve.X448;
    }

    static TlsSupportedGroup sect163k1() {
        return NamedCurve.SECT163K1;
    }

    static TlsSupportedGroup sect163r1() {
        return NamedCurve.SECT163R1;
    }

    static TlsSupportedGroup sect163r2() {
        return NamedCurve.SECT163R2;
    }

    static TlsSupportedGroup sect193r1() {
        return NamedCurve.SECT193R1;
    }

    static TlsSupportedGroup sect193r2() {
        return NamedCurve.SECT193R2;
    }

    static TlsSupportedGroup sect233k1() {
        return NamedCurve.SECT233K1;
    }

    static TlsSupportedGroup sect233r1() {
        return NamedCurve.SECT233R1;
    }

    static TlsSupportedGroup sect239k1() {
        return NamedCurve.SECT239K1;
    }

    static TlsSupportedGroup sect283k1() {
        return NamedCurve.SECT283K1;
    }

    static TlsSupportedGroup sect283r1() {
        return NamedCurve.SECT283R1;
    }

    static TlsSupportedGroup sect409k1() {
        return NamedCurve.SECT409K1;
    }

    static TlsSupportedGroup sect409r1() {
        return NamedCurve.SECT409R1;
    }

    static TlsSupportedGroup sect571k1() {
        return NamedCurve.SECT571K1;
    }

    static TlsSupportedGroup sect571r1() {
        return NamedCurve.SECT571R1;
    }

    static TlsSupportedGroup secp160k1() {
        return NamedCurve.SECP160K1;
    }

    static TlsSupportedGroup secp160r1() {
        return NamedCurve.SECP160R1;
    }

    static TlsSupportedGroup secp160r2() {
        return NamedCurve.SECP160R2;
    }

    static TlsSupportedGroup secp192k1() {
        return NamedCurve.SECP192K1;
    }

    static TlsSupportedGroup secp192r1() {
        return NamedCurve.SECP192R1;
    }

    static TlsSupportedGroup secp224k1() {
        return NamedCurve.SECP224K1;
    }

    static TlsSupportedGroup secp224r1() {
        return NamedCurve.SECP224R1;
    }

    static TlsSupportedGroup secp256k1() {
        return NamedCurve.SECP256K1;
    }

    static TlsSupportedGroup secp256r1() {
        return NamedCurve.SECP256R1;
    }

    static TlsSupportedGroup secp384r1() {
        return NamedCurve.SECP384R1;
    }

    static TlsSupportedGroup secp521r1() {
        return NamedCurve.SECP521R1;
    }

    static TlsSupportedGroup brainpoolp256r1() {
        return NamedCurve.BRAINPOOLP256R1;
    }

    static TlsSupportedGroup brainpoolp384r1() {
        return NamedCurve.BRAINPOOLP384R1;
    }

    static TlsSupportedGroup brainpoolp512r1() {
        return NamedCurve.BRAINPOOLP512R1;
    }

    static TlsSupportedGroup brainpoolp256r1Tls13() {
        return NamedCurve.BRAINPOOLP256R1TLS13;
    }

    static TlsSupportedGroup brainpoolp384r1Tls13() {
        return NamedCurve.BRAINPOOLP384R1TLS13;
    }

    static TlsSupportedGroup brainpoolp512r1Tls13() {
        return NamedCurve.BRAINPOOLP512R1TLS13;
    }

    static TlsSupportedGroup gc256a() {
        return NamedCurve.GC256A;
    }

    static TlsSupportedGroup gc256b() {
        return NamedCurve.GC256B;
    }

    static TlsSupportedGroup gc256c() {
        return NamedCurve.GC256C;
    }

    static TlsSupportedGroup gc256d() {
        return NamedCurve.GC256D;
    }

    static TlsSupportedGroup gc512a() {
        return NamedCurve.GC512A;
    }

    static TlsSupportedGroup gc512b() {
        return NamedCurve.GC512B;
    }

    static TlsSupportedGroup gc512c() {
        return NamedCurve.GC512C;
    }

    static TlsSupportedGroup ffdhe2048() {
        return NamedCurve.FFDHE2048;
    }

    static TlsSupportedGroup ffdhe3072() {
        return NamedCurve.FFDHE3072;
    }

    static TlsSupportedGroup ffdhe4096() {
        return NamedCurve.FFDHE4096;
    }

    static TlsSupportedGroup ffdhe6144() {
        return NamedCurve.FFDHE6144;
    }

    static TlsSupportedGroup ffdhe8192() {
        return NamedCurve.FFDHE8192;
    }

    static TlsSupportedGroup curvesM2() {
        return NamedCurve.CURVESM2;
    }
    
    static TlsSupportedGroup mlKem512() {
        return NamedCurve.ML_KEM_512;
    }

    static TlsSupportedGroup mlKem768() {
        return NamedCurve.ML_KEM_768;
    }

    static TlsSupportedGroup mlKem1024() {
        return NamedCurve.ML_KEM_1024;
    }

    static TlsSupportedGroup x25519MlKem768() {
        return NamedCurve.X25519MLKEM768;
    }

    static TlsSupportedGroup secp256r1MlKem768() {
        return NamedCurve.SECP256R1MLKEM768;
    }

    static TlsSupportedGroup explicitPrime(TlsKeyPairGenerator generator) {
        return new ExplicitPrime(generator);
    }

    static TlsSupportedGroup explicitChar2(TlsKeyPairGenerator generator) {
        return new ExplicitChar2(generator);
    }

    static TlsSupportedGroup reservedForPrivateUse(int id, boolean dtls) {
        return reservedForPrivateUse(id, dtls, null, null);
    }

    static TlsSupportedGroup reservedForPrivateUse(int id, boolean dtls, TlsKeyPairGenerator generator, TlsECParametersDecoder decoder) {
        return new Reserved(id, dtls, Objects.requireNonNullElseGet(generator, TlsKeyPairGenerator::unsupported), Objects.requireNonNullElseGet(decoder, TlsECParametersDecoder::unsupported));
    }

    int id();
    boolean dtls();

    final class NamedCurve implements TlsSupportedGroup {
        private static final TlsSupportedGroup SECT163K1 = new NamedCurve(1, true, TlsKeyPairGenerator.sect163k1());
        private static final TlsSupportedGroup SECT163R1 = new NamedCurve(2, true, TlsKeyPairGenerator.sect163r1());
        private static final TlsSupportedGroup SECT163R2 = new NamedCurve(3, true, TlsKeyPairGenerator.sect163r2());
        private static final TlsSupportedGroup SECT193R1 = new NamedCurve(4, true, TlsKeyPairGenerator.sect193r1());
        private static final TlsSupportedGroup SECT193R2 = new NamedCurve(5, true, TlsKeyPairGenerator.sect193r2());
        private static final TlsSupportedGroup SECT233K1 = new NamedCurve(6, true, TlsKeyPairGenerator.sect233k1());
        private static final TlsSupportedGroup SECT233R1 = new NamedCurve(7, true, TlsKeyPairGenerator.sect233r1());
        private static final TlsSupportedGroup SECT239K1 = new NamedCurve(8, true, TlsKeyPairGenerator.sect239k1());
        private static final TlsSupportedGroup SECT283K1 = new NamedCurve(9, true, TlsKeyPairGenerator.sect283k1());
        private static final TlsSupportedGroup SECT283R1 = new NamedCurve(10, true, TlsKeyPairGenerator.sect283r1());
        private static final TlsSupportedGroup SECT409K1 = new NamedCurve(11, true, TlsKeyPairGenerator.sect409k1());
        private static final TlsSupportedGroup SECT409R1 = new NamedCurve(12, true, TlsKeyPairGenerator.sect409r1());
        private static final TlsSupportedGroup SECT571K1 = new NamedCurve(13, true, TlsKeyPairGenerator.sect571k1());
        private static final TlsSupportedGroup SECT571R1 = new NamedCurve(14, true, TlsKeyPairGenerator.sect571r1());
        private static final TlsSupportedGroup SECP160K1 = new NamedCurve(15, true, TlsKeyPairGenerator.secp160k1());
        private static final TlsSupportedGroup SECP160R1 = new NamedCurve(16, true, TlsKeyPairGenerator.secp160r1());
        private static final TlsSupportedGroup SECP160R2 = new NamedCurve(17, true, TlsKeyPairGenerator.secp160r2());
        private static final TlsSupportedGroup SECP192K1 = new NamedCurve(18, true, TlsKeyPairGenerator.secp192k1());
        private static final TlsSupportedGroup SECP192R1 = new NamedCurve(19, true, TlsKeyPairGenerator.secp192r1());
        private static final TlsSupportedGroup SECP224K1 = new NamedCurve(20, true, TlsKeyPairGenerator.secp224k1());
        private static final TlsSupportedGroup SECP224R1 = new NamedCurve(21, true, TlsKeyPairGenerator.secp224r1());
        private static final TlsSupportedGroup SECP256K1 = new NamedCurve(22, true, TlsKeyPairGenerator.secp256k1());
        private static final TlsSupportedGroup SECP256R1 = new NamedCurve(23, true, TlsKeyPairGenerator.secp256r1());
        private static final TlsSupportedGroup SECP384R1 = new NamedCurve(24, true, TlsKeyPairGenerator.secp384r1());
        private static final TlsSupportedGroup SECP521R1 = new NamedCurve(25, true, TlsKeyPairGenerator.secp521r1());
        private static final TlsSupportedGroup BRAINPOOLP256R1 = new NamedCurve(26, true, TlsKeyPairGenerator.brainpoolp256r1());
        private static final TlsSupportedGroup BRAINPOOLP384R1 = new NamedCurve(27, true, TlsKeyPairGenerator.brainpoolp384r1());
        private static final TlsSupportedGroup BRAINPOOLP512R1 = new NamedCurve(28, true, TlsKeyPairGenerator.brainpoolp512r1());
        private static final TlsSupportedGroup X25519 = new NamedCurve(29, true, TlsKeyPairGenerator.x25519());
        private static final TlsSupportedGroup X448 = new NamedCurve(30, true, TlsKeyPairGenerator.x448());
        private static final TlsSupportedGroup BRAINPOOLP256R1TLS13 = new NamedCurve(31, true, TlsKeyPairGenerator.brainpoolp256r1());
        private static final TlsSupportedGroup BRAINPOOLP384R1TLS13 = new NamedCurve(32, true, TlsKeyPairGenerator.brainpoolp384r1());
        private static final TlsSupportedGroup BRAINPOOLP512R1TLS13 = new NamedCurve(33, true, TlsKeyPairGenerator.brainpoolp512r1());
        private static final TlsSupportedGroup GC256A = new NamedCurve(34, true, TlsKeyPairGenerator.gc256a());
        private static final TlsSupportedGroup GC256B = new NamedCurve(35, true, TlsKeyPairGenerator.gc256b());
        private static final TlsSupportedGroup GC256C = new NamedCurve(36, true, TlsKeyPairGenerator.gc256c());
        private static final TlsSupportedGroup GC256D = new NamedCurve(37, true, TlsKeyPairGenerator.gc256d());
        private static final TlsSupportedGroup GC512A = new NamedCurve(38, true, TlsKeyPairGenerator.gc512a());
        private static final TlsSupportedGroup GC512B = new NamedCurve(39, true, TlsKeyPairGenerator.gc512b());
        private static final TlsSupportedGroup GC512C = new NamedCurve(40, false, TlsKeyPairGenerator.gc512c());
        private static final TlsSupportedGroup CURVESM2 = new NamedCurve(41, true, TlsKeyPairGenerator.x25519());
        private static final TlsSupportedGroup FFDHE2048 = new NamedCurve(256, true, TlsKeyPairGenerator.ffdhe2048());
        private static final TlsSupportedGroup FFDHE3072 = new NamedCurve(257, true, TlsKeyPairGenerator.ffdhe3072());
        private static final TlsSupportedGroup FFDHE4096 = new NamedCurve(258, true, TlsKeyPairGenerator.ffdhe4096());
        private static final TlsSupportedGroup FFDHE6144 = new NamedCurve(259, true, TlsKeyPairGenerator.ffdhe6144());
        private static final TlsSupportedGroup FFDHE8192 = new NamedCurve(260, true, TlsKeyPairGenerator.ffdhe8192());
        private static final TlsSupportedGroup ML_KEM_512 = new NamedCurve(512, true, TlsKeyPairGenerator.mlKem512());
        private static final TlsSupportedGroup ML_KEM_768 = new NamedCurve(513, true, TlsKeyPairGenerator.mlKem768());
        private static final TlsSupportedGroup ML_KEM_1024 = new NamedCurve(514, true, TlsKeyPairGenerator.mlKem1024());
        private static final TlsSupportedGroup X25519MLKEM768 = new NamedCurve(4588, true, TlsKeyPairGenerator.x25519());
        private static final TlsSupportedGroup SECP256R1MLKEM768 = new NamedCurve(4587, true, TlsKeyPairGenerator.secp256r1());

        private final int id;
        private final boolean dtls;
        private final TlsKeyPairGenerator generator;

        private NamedCurve(int id, boolean dtls, TlsKeyPairGenerator generator) {
            this.id = id;
            this.dtls = dtls;
            this.generator = generator;
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
        public TlsECParameters decodeParameters(ByteBuffer buffer) {
            return TlsECParametersDecoder.namedCurve()
                    .decodeParameters(buffer);
        }

        @Override
        public KeyPair generate(TlsVersion version) {
            return generator.generate(version);
        }
    }

    final class ExplicitPrime implements TlsSupportedGroup {
        private final TlsKeyPairGenerator generator;

        private ExplicitPrime(TlsKeyPairGenerator generator) {
            this.generator = generator;
        }

        @Override
        public int id() {
            return 65281;
        }

        @Override
        public boolean dtls() {
            return true;
        }

        @Override
        public TlsECParameters decodeParameters(ByteBuffer buffer) {
            return TlsECParametersDecoder.explicitPrime()
                    .decodeParameters(buffer);
        }

        @Override
        public KeyPair generate(TlsVersion version) {
            return generator.generate(version);
        }
    }

    final class ExplicitChar2 implements TlsSupportedGroup {
        private final TlsKeyPairGenerator generator;

        private ExplicitChar2(TlsKeyPairGenerator generator) {
            this.generator = generator;
        }

        @Override
        public int id() {
            return 65282;
        }

        @Override
        public boolean dtls() {
            return true;
        }

        @Override
        public TlsECParameters decodeParameters(ByteBuffer buffer) {
            return TlsECParametersDecoder.explicitChar2()
                    .decodeParameters(buffer);
        }

        @Override
        public KeyPair generate(TlsVersion version) {
            return generator.generate(version);
        }
    }

    non-sealed class Reserved implements TlsSupportedGroup {
        private final int id;
        private final boolean dtls;
        private final TlsKeyPairGenerator generator;
        private final TlsECParametersDecoder decoder;

        private Reserved(int id, boolean dtls, TlsKeyPairGenerator generator, TlsECParametersDecoder decoder) {
            if(id < 0 || id > 65535) {
                throw new TlsException("Invalid reserved supported group: expected unsigned int16");
            }

            this.id = id;
            this.dtls = dtls;
            this.generator = generator;
            this.decoder = decoder;
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
        public TlsECParameters decodeParameters(ByteBuffer buffer) {
            return decoder.decodeParameters(buffer);
        }

        @Override
        public KeyPair generate(TlsVersion version) {
            return generator.generate(version);
        }
    }
}
