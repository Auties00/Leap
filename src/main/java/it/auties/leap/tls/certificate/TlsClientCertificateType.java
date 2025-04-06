package it.auties.leap.tls.certificate;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.property.TlsIdentifiableProperty;

import java.net.URI;

// For historical reasons, the names of some client certificate types
// include the algorithm used to sign the certificate.  For example,
// in earlier versions of TLS, rsa_fixed_dh meant a certificate
// signed with RSA and containing a static DH key.  In TLS 1.2, this
// functionality has been obsoleted by the
// supported_signature_algorithms, and the certificate type no longer
// restricts the algorithm used to sign the certificate.  For
// example, if the server sends dss_fixed_dh certificate type and
// {{sha1, dsa}, {sha1, rsa}} signature types, the client MAY reply
// with a certificate containing a static DH key, signed with RSA-SHA1.
// https://www.iana.org/assignments/tls-parameters/tls-parameters-2.csv
public sealed interface TlsClientCertificateType extends TlsIdentifiableProperty<Byte> {
    static RsaSign rsaSign() {
        return RsaSign.INSTANCE;
    }

    static DssSign dssSign() {
        return DssSign.INSTANCE;
    }

    static RsaFixedDh rsaFixedDh() {
        return RsaFixedDh.INSTANCE;
    }

    static DssFixedDh dssFixedDh() {
        return DssFixedDh.INSTANCE;
    }

    static RsaEphemeralDh rsaEphemeralDh() {
        return RsaEphemeralDh.INSTANCE;
    }

    static DssEphemeralDh dssEphemeralDh() {
        return DssEphemeralDh.INSTANCE;
    }

    static FortezzaDms fortezzaDms() {
        return FortezzaDms.INSTANCE;
    }

    static EcdsaSign ecdsaSign() {
        return EcdsaSign.INSTANCE;
    }

    static RsaFixedEcdh rsaFixedEcdh() {
        return RsaFixedEcdh.INSTANCE;
    }

    static EcdsaFixedEcdh ecdsaFixedEcdh() {
        return EcdsaFixedEcdh.INSTANCE;
    }

    static GostSign256 gostSign256() {
        return GostSign256.INSTANCE;
    }

    static GostSign512 gostSign512() {
        return GostSign512.INSTANCE;
    }

    static TlsClientCertificateType reserved(byte id) {
        if(id < -32 || id > -1) {
            throw new TlsAlert(
                    "Only values from 224-255 (decimal) inclusive are reserved",
                    URI.create("https://www.ietf.org/rfc/rfc3749.txt"),
                    "2"
            );
        }

        return new Reserved(id);
    }

    final class RsaSign implements TlsClientCertificateType {
        private static final RsaSign INSTANCE = new RsaSign();

        @Override
        public Byte id() {
            return 1;
        }
    }

    final class DssSign implements TlsClientCertificateType {
        private static final DssSign INSTANCE = new DssSign();

        @Override
        public Byte id() {
            return 2;
        }
    }

    final class RsaFixedDh implements TlsClientCertificateType {
        private static final RsaFixedDh INSTANCE = new RsaFixedDh();

        @Override
        public Byte id() {
            return 3;
        }
    }

    final class DssFixedDh implements TlsClientCertificateType {
        private static final DssFixedDh INSTANCE = new DssFixedDh();

        @Override
        public Byte id() {
            return 4;
        }
    }

    final class RsaEphemeralDh implements TlsClientCertificateType {
        private static final RsaEphemeralDh INSTANCE = new RsaEphemeralDh();

        @Override
        public Byte id() {
            return 5;
        }
    }

    final class DssEphemeralDh implements TlsClientCertificateType {
        private static final DssEphemeralDh INSTANCE = new DssEphemeralDh();

        @Override
        public Byte id() {
            return 6;
        }
    }

    final class FortezzaDms implements TlsClientCertificateType {
        private static final FortezzaDms INSTANCE = new FortezzaDms();

        @Override
        public Byte id() {
            return 20;
        }
    }

    final class EcdsaSign implements TlsClientCertificateType {
        private static final EcdsaSign INSTANCE = new EcdsaSign();

        @Override
        public Byte id() {
            return 64;
        }
    }

    final class RsaFixedEcdh implements TlsClientCertificateType {
        private static final RsaFixedEcdh INSTANCE = new RsaFixedEcdh();

        @Override
        public Byte id() {
            return 65;
        }
    }

    final class EcdsaFixedEcdh implements TlsClientCertificateType {
        private static final EcdsaFixedEcdh INSTANCE = new EcdsaFixedEcdh();

        @Override
        public Byte id() {
            return 66;
        }
    }

    final class GostSign256 implements TlsClientCertificateType {
        private static final GostSign256 INSTANCE = new GostSign256();

        @Override
        public Byte id() {
            return 67;
        }
    }

    final class GostSign512 implements TlsClientCertificateType {
        private static final GostSign512 INSTANCE = new GostSign512();

        @Override
        public Byte id() {
            return 68;
        }
    }

    final class Reserved implements TlsClientCertificateType {
        private final byte id;

        private Reserved(byte id) {
            this.id = id;
        }

        @Override
        public Byte id() {
            return id;
        }
    }
}
