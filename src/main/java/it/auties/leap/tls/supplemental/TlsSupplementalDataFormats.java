package it.auties.leap.tls.supplemental;

public sealed interface TlsSupplementalDataFormats {
    static UserMappingData userMappingData() {
        return UserMappingData.INSTANCE;
    }

    static AuthorizationData authorizationData() {
        return AuthorizationData.INSTANCE;
    }

    static TlsSupplementalDataFormats reservedForPrivateUse(int id) {
        if(id < 65280 || id > 65535) {
            throw new IllegalArgumentException("Only values from 65280-65535 (decimal) inclusive are reserved for Private Use");
        }

        return new Reserved(id);
    }

    int id();

    final class UserMappingData implements TlsSupplementalDataFormats {
        private static final UserMappingData INSTANCE = new UserMappingData();

        @Override
        public int id() {
            return 0;
        }
    }

    final class AuthorizationData implements TlsSupplementalDataFormats {
        private static final AuthorizationData INSTANCE = new AuthorizationData();

        @Override
        public int id() {
            return 16386;
        }
    }

    final class Reserved implements TlsSupplementalDataFormats {
        private final int id;

        private Reserved(int id) {
            this.id = id;
        }

        @Override
        public int id() {
            return id;
        }
    }
}
