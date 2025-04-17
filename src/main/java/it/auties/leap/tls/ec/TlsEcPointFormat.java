package it.auties.leap.tls.ec;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
import it.auties.leap.tls.property.TlsIdentifiableProperty;

import java.util.List;

public sealed interface TlsEcPointFormat extends TlsIdentifiableProperty<Byte> {
    static TlsEcPointFormat uncompressed() {
        return Uncompressed.INSTANCE;
    }

    static TlsEcPointFormat ansix962CompressedPrime() {
        return Ansix962CompressedPrime.INSTANCE;
    }

    static TlsEcPointFormat ansix962CompressedChar2() {
        return Ansix962CompressedChar2.INSTANCE;
    }

    static TlsEcPointFormat reservedForPrivateUse(byte id) {
        if (id < -8 || id > -1) {
            throw new TlsAlert("Only values from 248-255 (decimal) inclusive are reserved for Private Use", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
        }

        return new Reserved(id);
    }

    static List<TlsEcPointFormat> values() {
        final class Formats {
            private static final List<TlsEcPointFormat> FORMATS = List.of(Uncompressed.INSTANCE, Ansix962CompressedPrime.INSTANCE, Ansix962CompressedChar2.INSTANCE);
        }

        return Formats.FORMATS;
    }

    final class Uncompressed implements TlsEcPointFormat {
        private static final Uncompressed INSTANCE = new Uncompressed();

        @Override
        public Byte id() {
            return 0;
        }
    }

    final class Ansix962CompressedPrime implements TlsEcPointFormat {
        private static final Ansix962CompressedPrime INSTANCE = new Ansix962CompressedPrime();

        @Override
        public Byte id() {
            return 1;
        }
    }

    final class Ansix962CompressedChar2 implements TlsEcPointFormat {
        private static final Ansix962CompressedChar2 INSTANCE = new Ansix962CompressedChar2();

        @Override
        public Byte id() {
            return 2;
        }
    }

    final class Reserved implements TlsEcPointFormat {
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
