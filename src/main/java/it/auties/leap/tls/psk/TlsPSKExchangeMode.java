package it.auties.leap.tls.psk;

import it.auties.leap.tls.version.TlsVersion;
import it.auties.leap.tls.exception.TlsException;

import java.net.URI;
import java.util.Objects;
import java.util.Optional;

// https://www.iana.org/assignments/tls-parameters/tls-pskkeyexchangemode.csv
public sealed interface TlsPSKExchangeMode extends TlsPSKExchangeModeGenerator {
    static TlsPSKExchangeMode pskKe() {
        return KE.INSTANCE;
    }

    static TlsPSKExchangeMode pskDheKe() {
        return DHEKE.INSTANCE;
    }

    static TlsPSKExchangeMode reservedForPrivateUse(byte id) {
        return reservedForPrivateUse(id, null);
    }

    static TlsPSKExchangeMode reservedForPrivateUse(byte id, TlsPSKExchangeModeGenerator generator) {
        if(id != -32 && id != -31) {
            throw new TlsException(
                    "Only values from 224-255 (decimal) inclusive are reserved for Private Use",
                    URI.create("https://www.rfc-editor.org/rfc/rfc8446.html"),
                    "11"
            );
        }

        return new Reserved(id, Objects.requireNonNullElseGet(generator, TlsPSKExchangeModeGenerator::unsupported));
    }

    byte id();

    final class KE implements TlsPSKExchangeMode {
        private static final KE INSTANCE = new KE();

        @Override
        public byte id() {
            return 0;
        }

        @Override
        public Optional<byte[]> generate(TlsVersion version) {
            return Optional.empty();
        }
    }

    final class DHEKE implements TlsPSKExchangeMode {
        private static final DHEKE INSTANCE = new DHEKE();

        @Override
        public byte id() {
            return 1;
        }

        @Override
        public Optional<byte[]> generate(TlsVersion version) {
            return Optional.empty();
        }
    }

    non-sealed class Reserved implements TlsPSKExchangeMode {
        private final byte id;
        private final TlsPSKExchangeModeGenerator generator;

        protected Reserved(byte id, TlsPSKExchangeModeGenerator generator) {
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
    }
}
