package it.auties.leap.tls.key;

import it.auties.leap.tls.config.TlsVersion;
import it.auties.leap.tls.exception.TlsException;

import java.net.URI;
import java.util.Objects;
import java.util.Optional;

// https://www.iana.org/assignments/tls-parameters/tls-pskkeyexchangemode.csv
public sealed interface TlsPskKeyExchangeMode {
    static TlsPskKeyExchangeMode pskKe() {
        return PskKe.INSTANCE;
    }

    static TlsPskKeyExchangeMode pskDheKe() {
        return PskDheKe.INSTANCE;
    }

    static TlsPskKeyExchangeMode reservedForPrivateUse(byte id, Reserved.Generator generator) {
        if(id != -32 && id != -31) {
            throw new TlsException(
                    "Only values from 224-255 (decimal) inclusive are reserved for Private Use",
                    URI.create("https://www.rfc-editor.org/rfc/rfc8446.html"),
                    "11"
            );
        }

        return new Reserved(id, Objects.requireNonNullElseGet(generator, Reserved.Generator::unsupported));
    }

    Optional<byte[]> generate(TlsVersion version);

    byte id();

    final class PskKe implements TlsPskKeyExchangeMode {
        private static final PskKe INSTANCE = new PskKe();

        @Override
        public byte id() {
            return 0;
        }

        @Override
        public Optional<byte[]> generate(TlsVersion version) {
            return Optional.empty();
        }
    }

    final class PskDheKe implements TlsPskKeyExchangeMode {
        private static final PskDheKe INSTANCE = new PskDheKe();

        @Override
        public byte id() {
            return 1;
        }

        @Override
        public Optional<byte[]> generate(TlsVersion version) {
            return Optional.empty();
        }
    }

    final class Reserved implements TlsPskKeyExchangeMode {
        private final byte id;
        private final Generator generator;
        private Reserved(byte id, Generator generator) {
            this.id = id;
            this.generator = generator;
        }

        @Override
        public byte id() {
            return id;
        }

        @Override
        public Optional<byte[]> generate(TlsVersion version) {
            return generator.generate(version);
        }

        @FunctionalInterface
        public interface Generator {
            Optional<byte[]> generate(TlsVersion version);

            static Generator unsupported() {
                return Unsupported.INSTANCE;
            }
        }

        private static final class Unsupported implements Generator {
            private static final Unsupported INSTANCE = new Unsupported();

            private Unsupported() {

            }

            @Override
            public Optional<byte[]> generate(TlsVersion version) {
                return Optional.empty();
            }
        }
    }
}
