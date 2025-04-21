package it.auties.leap.tls.supplemental;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
import it.auties.leap.tls.property.TlsIdentifiableProperty;

public sealed interface TlsSupplementalDataFormats extends TlsIdentifiableProperty<Integer> {
    static UserMappingData userMappingData() {
        return UserMappingData.INSTANCE;
    }

    static AuthorizationData authorizationData() {
        return AuthorizationData.INSTANCE;
    }

    static TlsSupplementalDataFormats reservedForPrivateUse(int id) {
        if(id < 65280 || id > 65535) {
            throw new TlsAlert(
                    "Only values from 65280-65535 (decimal) inclusive are reserved for Private Use",
                    TlsAlertLevel.FATAL,
                    TlsAlertType.INTERNAL_ERROR
            );
        }

        return new Reserved(id);
    }

    final class UserMappingData implements TlsSupplementalDataFormats {
        private static final UserMappingData INSTANCE = new UserMappingData();

        @Override
        public Integer id() {
            return 0;
        }
    }

    final class AuthorizationData implements TlsSupplementalDataFormats {
        private static final AuthorizationData INSTANCE = new AuthorizationData();

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
