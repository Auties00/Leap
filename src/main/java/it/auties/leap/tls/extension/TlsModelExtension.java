package it.auties.leap.tls.extension;

import it.auties.leap.tls.TlsExtension;
import it.auties.leap.tls.TlsVersion;
import it.auties.leap.tls.extension.model.ClientSupportedVersionsModel;
import it.auties.leap.tls.extension.model.KeyShareExtensionModel;
import it.auties.leap.tls.extension.model.PaddingExtensionModel;
import it.auties.leap.tls.extension.model.SNIExtensionModel;

import java.util.List;
import java.util.Optional;
import java.util.Set;

public sealed abstract class TlsModelExtension<CONFIG extends TlsModelExtension.Config, RESULT extends TlsConcreteExtension> implements TlsExtension
        permits KeyShareExtensionModel, PaddingExtensionModel, SNIExtensionModel, ClientSupportedVersionsModel {

    public abstract Optional<RESULT> create(CONFIG config);
    public abstract List<TlsVersion> versions();
    public abstract Class<RESULT> resultType();
    public abstract Dependencies dependencies();

    public sealed interface Config
            permits KeyShareExtensionModel.Config, PaddingExtensionModel.Config, SNIExtensionModel.Config, ClientSupportedVersionsModel.Config {
    }

    public sealed interface Dependencies {
        static None none() {
            return None.INSTANCE;
        }

        @SafeVarargs
        static Some some(Class<? extends TlsConcreteExtension>... includedTypes) {
            return new Some(Set.of(includedTypes));
        }

        static All all() {
            return All.INSTANCE;
        }

        final class None implements Dependencies {
            private static final None INSTANCE = new None();
            private None() {

            }
        }

        final class Some implements Dependencies {
            private final Set<Class<? extends TlsConcreteExtension>> includedTypes;
            private Some(Set<Class<? extends TlsConcreteExtension>> includedTypes) {
                this.includedTypes = includedTypes;
            }

            public Set<Class<? extends TlsConcreteExtension>> includedTypes() {
                return includedTypes;
            }
        }

        final class All implements Dependencies {
            private static final All INSTANCE = new All();
            private All() {

            }
        }
    }
}
