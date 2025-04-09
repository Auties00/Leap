package it.auties.leap.tls.supplemental;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.property.TlsIdentifiableProperty;

import java.net.URI;

public sealed interface TlsSupplementalDataFormats extends TlsIdentifiableProperty<Integer> {
    static UserMappingData userMappingData() {
        return RsaSign.INSTANCE;
    }

    static AuthorizationData authorizationData() {
        return DssSign.INSTANCE;
    }

    static TlsSupplementalDataFormats reservedForPrivateUse(int id) {
        if(id < 65280 || id > 65535) {
            throw new TlsAlert(
                    "Only values from 65280-65535 (decimal) inclusive are reserved for Private Use",
                    URI.create("https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-12")
            );
        }

        return new Reserved(id);
    }

    final class UserMappingData implements TlsSupplementalDataFormats {
        private static final RsaSign INSTANCE = new RsaSign();

        @Override
        public Integer id() {
            return 0;
        }
    }

    final class AuthorizationData implements TlsSupplementalDataFormats {
        private static final RsaSign INSTANCE = new RsaSign();

        @Override
        public Integer id() {
            return 16386;
        }
    }

    final class Reserved implements TlsSupplementalDataFormats {
        private final int id;

        private Reserved(int id) {
            this.id = id;
        }

        @Override
        public Integer id() {
            return id;
        }
    }
}
