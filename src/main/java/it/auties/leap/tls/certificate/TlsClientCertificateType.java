package it.auties.leap.tls.certificate;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.property.TlsIdentifiableProperty;
import it.auties.leap.tls.signature.TlsSignatureAlgorithm.Signature;
import org.bouncycastle.jcajce.interfaces.XDHPublicKey;

import javax.crypto.interfaces.DHPublicKey;
import java.net.URI;
import java.security.interfaces.XECPublicKey;
import java.util.Collections;
import java.util.Set;
import java.util.function.Function;

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

    static GostSign256 falconSign() {
        return GostSign256.INSTANCE;
    }

    static GostSign512 dilithiumSign() {
        return GostSign512.INSTANCE;
    }

    Set<Signature> signatures();

    boolean accepts(TlsCertificate certificate);

    static TlsClientCertificateType reservedForPrivateUse(byte id, Set<Signature> signatures) {
        return reservedForPrivateUse(id, signatures, null);
    }

      static TlsClientCertificateType reservedForPrivateUse(byte id, Set<Signature> signatures, Function<TlsCertificate, Boolean> validator) {
        if(id < -32 || id > -1) {
            throw new TlsAlert(
                    "Only values from 224-255 (decimal) inclusive are reserved for Private Use",
                    URI.create("https://www.ietf.org/rfc/rfc3749.txt"),
                    "2"
            );
        }

        if(signatures == null || signatures.isEmpty()) {
            throw new TlsAlert("Expected a set of signatures");
        }

        return new Reserved(id, signatures, validator);
    }

    final class RsaSign implements TlsClientCertificateType {
        private static final RsaSign INSTANCE = new RsaSign();

        @Override
        public Byte id() {
            return 1;
        }

        @Override
        public Set<Signature> signatures() {
            return Set.of(Signature.rsa(), Signature.rsaPssPssSha256(), Signature.rsaPssPssSha384(), Signature.rsaPssPssSha512(), Signature.rsaPssRsaeSha256(), Signature.rsaPssRsaeSha384(), Signature.rsaPssRsaeSha512());
        }

        @Override
        public boolean accepts(TlsCertificate certificate) {
            return true;
        }
    }

    final class DssSign implements TlsClientCertificateType {
        private static final DssSign INSTANCE = new DssSign();

        @Override
        public Byte id() {
            return 2;
        }

        @Override
        public Set<Signature> signatures() {
            return Set.of(Signature.dsa());
        }

        @Override
        public boolean accepts(TlsCertificate certificate) {
            return true;
        }
    }

    final class RsaFixedDh implements TlsClientCertificateType {
        private static final RsaFixedDh INSTANCE = new RsaFixedDh();

        @Override
        public Byte id() {
            return 3;
        }

        @Override
        public Set<Signature> signatures() {
            return Set.of(Signature.rsa(), Signature.rsaPssPssSha256(), Signature.rsaPssPssSha384(), Signature.rsaPssPssSha512(), Signature.rsaPssRsaeSha256(), Signature.rsaPssRsaeSha384(), Signature.rsaPssRsaeSha512());
        }

        @Override
        public boolean accepts(TlsCertificate certificate) {
            return certificate.value().getPublicKey() instanceof DHPublicKey;
        }
    }

    final class DssFixedDh implements TlsClientCertificateType {
        private static final DssFixedDh INSTANCE = new DssFixedDh();

        @Override
        public Byte id() {
            return 4;
        }

        @Override
        public Set<Signature> signatures() {
            return Set.of(Signature.dsa());
        }

        @Override
        public boolean accepts(TlsCertificate certificate) {
            return certificate.value().getPublicKey() instanceof DHPublicKey;
        }
    }

    final class RsaEphemeralDh implements TlsClientCertificateType {
        private static final RsaEphemeralDh INSTANCE = new RsaEphemeralDh();

        @Override
        public Byte id() {
            return 5;
        }

        @Override
        public Set<Signature> signatures() {
            return Set.of(Signature.rsa(), Signature.rsaPssPssSha256(), Signature.rsaPssPssSha384(), Signature.rsaPssPssSha512(), Signature.rsaPssRsaeSha256(), Signature.rsaPssRsaeSha384(), Signature.rsaPssRsaeSha512());
        }

        @Override
        public boolean accepts(TlsCertificate certificate) {
            return certificate.value().getPublicKey() instanceof DHPublicKey;
        }
    }

    final class DssEphemeralDh implements TlsClientCertificateType {
        private static final DssEphemeralDh INSTANCE = new DssEphemeralDh();

        @Override
        public Byte id() {
            return 6;
        }

        @Override
        public Set<Signature> signatures() {
            return Set.of(Signature.dsa());
        }

        @Override
        public boolean accepts(TlsCertificate certificate) {
            return certificate.value().getPublicKey() instanceof DHPublicKey;
        }
    }

    final class FortezzaDms implements TlsClientCertificateType {
        private static final FortezzaDms INSTANCE = new FortezzaDms();

        @Override
        public Byte id() {
            return 20;
        }

        @Override
        public Set<Signature> signatures() {
            return Set.of(Signature.dsa());
        }

        @Override
        public boolean accepts(TlsCertificate certificate) {
            return true;
        }
    }

    final class EcdsaSign implements TlsClientCertificateType {
        private static final EcdsaSign INSTANCE = new EcdsaSign();

        @Override
        public Byte id() {
            return 64;
        }

        @Override
        public Set<Signature> signatures() {
            return Set.of(Signature.ecdsa());
        }

        @Override
        public boolean accepts(TlsCertificate certificate) {
            return true;
        }
    }

    final class RsaFixedEcdh implements TlsClientCertificateType {
        private static final RsaFixedEcdh INSTANCE = new RsaFixedEcdh();

        @Override
        public Byte id() {
            return 65;
        }

        @Override
        public Set<Signature> signatures() {
            return Set.of(Signature.rsa(), Signature.rsaPssPssSha256(), Signature.rsaPssPssSha384(), Signature.rsaPssPssSha512(), Signature.rsaPssRsaeSha256(), Signature.rsaPssRsaeSha384(), Signature.rsaPssRsaeSha512());
        }

        @Override
        public boolean accepts(TlsCertificate certificate) {
            var publicKey = certificate.value().getPublicKey();
            return publicKey instanceof XECPublicKey || publicKey instanceof XDHPublicKey;
        }
    }

    final class EcdsaFixedEcdh implements TlsClientCertificateType {
        private static final EcdsaFixedEcdh INSTANCE = new EcdsaFixedEcdh();

        @Override
        public Byte id() {
            return 66;
        }

        @Override
        public Set<Signature> signatures() {
            return Set.of(Signature.ecdsa());
        }

        @Override
        public boolean accepts(TlsCertificate certificate) {
            var publicKey = certificate.value().getPublicKey();
            return publicKey instanceof XECPublicKey || publicKey instanceof XDHPublicKey;
        }
    }

    final class GostSign256 implements TlsClientCertificateType {
        private static final GostSign256 INSTANCE = new GostSign256();

        @Override
        public Byte id() {
            return 67;
        }

        @Override
        public Set<Signature> signatures() {
            return Set.of(Signature.gostr34102012_256());
        }

        @Override
        public boolean accepts(TlsCertificate certificate) {
            return true;
        }
    }

    final class GostSign512 implements TlsClientCertificateType {
        private static final GostSign512 INSTANCE = new GostSign512();

        @Override
        public Byte id() {
            return 68;
        }

        @Override
        public Set<Signature> signatures() {
            return Set.of(Signature.gostr34102012_512());
        }

        @Override
        public boolean accepts(TlsCertificate certificate) {
            return true;
        }
    }

    final class Reserved implements TlsClientCertificateType {
        private final byte id;
        private final Set<Signature> signatures;
        private final Function<TlsCertificate, Boolean> validator;

        private Reserved(byte id, Set<Signature> signatures, Function<TlsCertificate, Boolean> validator) {
            this.id = id;
            this.signatures = signatures;
            this.validator = validator;
        }

        @Override
        public Byte id() {
            return id;
        }

        @Override
        public Set<Signature> signatures() {
            return Collections.unmodifiableSet(signatures);
        }

        @Override
        public boolean accepts(TlsCertificate certificate) {
            return validator == null || validator.apply(certificate);
        }
    }
}
