package it.auties.leap.tls.ec;

import it.auties.leap.tls.exception.TlsException;

import java.net.URI;

public sealed interface TlsECPointFormat {
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

    byte id();

    final class Uncompressed implements TlsECPointFormat {
        private static final Uncompressed INSTANCE = new Uncompressed();

        @Override
        public byte id() {
            return 0;
        }
    }

    final class Ansix962CompressedPrime implements TlsECPointFormat {
        private static final Ansix962CompressedPrime INSTANCE = new Ansix962CompressedPrime();

        @Override
        public byte id() {
            return 1;
        }
    }

    final class Ansix962CompressedChar2 implements TlsECPointFormat {
        private static final Ansix962CompressedChar2 INSTANCE = new Ansix962CompressedChar2();

        @Override
        public byte id() {
            return 2;
        }
    }

    final class Reserved implements TlsECPointFormat {
        private final byte id;
        private Reserved(byte id) {
            this.id = id;
        }

        @Override
        public byte id() {
            return id;
        }
    }
}
