package it.auties.leap.tls.certificate;

import it.auties.leap.tls.TlsException;
import it.auties.leap.tls.property.TlsIdentifiableProperty;

import java.net.URI;

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

    static FalconSign falconSign() {
        return FalconSign.INSTANCE;
    }

    static DilithiumSign dilithiumSign() {
        return DilithiumSign.INSTANCE;
    }

    static TlsClientCertificateType reservedForPrivateUse(byte id) {
        if(id < -32 || id > -1) {
            throw new TlsException(
                    "Only values from 224-255 (decimal) inclusive are reserved for Private Use",
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

    final class FalconSign implements TlsClientCertificateType {
        private static final FalconSign INSTANCE = new FalconSign();

        @Override
        public Byte id() {
            return 67;
        }
    }

    final class DilithiumSign implements TlsClientCertificateType {
        private static final DilithiumSign INSTANCE = new DilithiumSign();

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
