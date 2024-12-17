package it.auties.leap.tls.config;

import it.auties.leap.tls.exception.TlsException;

import java.net.URI;

// TODO: Do we need this?
public sealed interface TlsEcPointFormat extends TlsIdentifiable.Int8<TlsEcPointFormat> {
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
        if(id < -8 || id > -1) {
            throw new TlsException(
                    "Only values from 248-255 (decimal) inclusive are reserved for Private Use",
                    URI.create("https://www.rfc-editor.org/rfc/rfc8422.html"),
                    "5.1.2"
            );
        }

        return new Reserved(id);
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
