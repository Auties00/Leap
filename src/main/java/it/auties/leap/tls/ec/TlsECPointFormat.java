package it.auties.leap.tls.ec;

import it.auties.leap.tls.TlsException;
import it.auties.leap.tls.property.TlsIdentifiableProperty;

import java.net.URI;
import java.util.List;

public sealed interface TlsECPointFormat extends TlsIdentifiableProperty<Byte> {
    static TlsECPointFormat uncompressed() {
        return Uncompressed.INSTANCE;
    }

    static TlsECPointFormat ansix962CompressedPrime() {
        return Ansix962CompressedPrime.INSTANCE;
    }

    static TlsECPointFormat ansix962CompressedChar2() {
        return Ansix962CompressedChar2.INSTANCE;
    }

    static TlsECPointFormat reservedForPrivateUse(byte id) {
        if(id < -8 || id > -1) {
            throw new TlsException(
                    "Only values from 248-255 (decimal) inclusive are reserved for Private Use",
                    URI.create("https://www.rfc-editor.org/rfc/rfc8422.html"),
                    "5.1.2"
            );
        }

        return new Reserved(id);
    }

    static List<TlsECPointFormat> values() {
        final class Formats {
            private static final List<TlsECPointFormat> FORMATS = List.of(Uncompressed.INSTANCE, Ansix962CompressedPrime.INSTANCE, Ansix962CompressedChar2.INSTANCE);
        }

        return Formats.FORMATS;
    }

    final class Uncompressed implements TlsECPointFormat {
        private static final Uncompressed INSTANCE = new Uncompressed();

        @Override
        public Byte id() {
            return 0;
        }
    }

    final class Ansix962CompressedPrime implements TlsECPointFormat {
        private static final Ansix962CompressedPrime INSTANCE = new Ansix962CompressedPrime();

        @Override
        public Byte id() {
            return 1;
        }
    }

    final class Ansix962CompressedChar2 implements TlsECPointFormat {
        private static final Ansix962CompressedChar2 INSTANCE = new Ansix962CompressedChar2();

        @Override
        public Byte id() {
            return 2;
        }
    }

    final class Reserved implements TlsECPointFormat {
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
