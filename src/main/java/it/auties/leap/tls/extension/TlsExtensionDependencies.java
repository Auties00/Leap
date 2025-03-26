package it.auties.leap.tls.extension;

import java.util.Set;

sealed public interface TlsExtensionDependencies {
    static None none() {
        return None.INSTANCE;
    }

    static Some some(Integer... includedTypes) {
        return new Some(Set.of(includedTypes));
    }

    static All all() {
        return All.INSTANCE;
    }

    final class None implements TlsExtensionDependencies {
        private static final None INSTANCE = new None();

        private None() {

        }
    }

    final class Some implements TlsExtensionDependencies {
        private final Set<Integer> includedTypes;

        private Some(Set<Integer> includedTypes) {
            this.includedTypes = includedTypes;
        }

        public Set<Integer> includedTypes() {
            return includedTypes;
        }
    }

    final class All implements TlsExtensionDependencies {
        private static final All INSTANCE = new All();

        private All() {

        }
    }
}
