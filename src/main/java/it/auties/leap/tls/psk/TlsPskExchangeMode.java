package it.auties.leap.tls.psk;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.property.TlsIdentifiableProperty;
import it.auties.leap.tls.version.TlsVersion;

import java.net.URI;
import java.util.Optional;

// https://www.iana.org/assignments/tls-parameters/tls-pskkeyexchangemode.csv
public sealed interface TlsPskExchangeMode extends TlsIdentifiableProperty<Byte>, TlsPskExchangeModeGenerator {
    static TlsPskExchangeMode pskKe() {
        return KE.INSTANCE;
    }

    static TlsPskExchangeMode pskDheKe() {
        return DHEKE.INSTANCE;
    }

    static TlsPskExchangeMode reservedForPrivateUse(byte id) {
        return new Reserved(id, null);
    }

    static TlsPskExchangeMode reservedForPrivateUse(byte id, TlsPskExchangeModeGenerator generator) {
        return new Reserved(id, generator);
    }

    final class KE implements TlsPskExchangeMode {
        private static final KE INSTANCE = new KE();

        @Override
        public Byte id() {
            return 0;
        }

        @Override
        public Optional<byte[]> generate(TlsVersion version) {
            return Optional.empty();
        }
    }

    final class DHEKE implements TlsPskExchangeMode {
        private static final DHEKE INSTANCE = new DHEKE();

        @Override
        public Byte id() {
            return 1;
        }

        @Override
        public Optional<byte[]> generate(TlsVersion version) {
            return Optional.empty();
        }
    }

    final class Reserved implements TlsPskExchangeMode {
        private final byte id;
        private final TlsPskExchangeModeGenerator generator;

        private Reserved(byte id, TlsPskExchangeModeGenerator generator) {
            if(id != -32 && id != -31) {
                throw new TlsAlert(
                        "Only values from 224-255 (decimal) inclusive are reserved for Private Use",
                        URI.create("https://www.rfc-editor.org/rfc/rfc8446.html"),
                        "11"
                );
            }

            this.id = id;
            this.generator = generator;
        }

        @Override
        public Byte id() {
            return id;
        }

        @Override
        public Optional<byte[]> generate(TlsVersion version) {
            if(generator == null) {
                throw TlsAlert.stub();
            }else {
                return generator.generate(version);
            }
        }
    }
}
