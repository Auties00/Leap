package it.auties.leap.tls.config;

import java.util.Optional;

@SuppressWarnings("unused")
public sealed interface TlsIdentifiableUnion<O extends TlsIdentifiable<O, P>, P extends Number> {
    static <O extends TlsIdentifiable<O, P>, P extends Number> TlsIdentifiableUnion<O, P> of(O value) {
        return new Value<>(value);
    }

    static <O extends TlsIdentifiable<O, P>, P extends Number> TlsIdentifiableUnion<O, P> of(P value) {
        return new Identifier<>(value);
    }

    P id();

    Optional<O> value();

    final class Value<O extends TlsIdentifiable<O, P>, P extends Number> implements TlsIdentifiableUnion<O, P> {
        private final O value;
        private Value(O value) {
            this.value = value;
        }

        @Override
        public P id() {
            return value.id();
        }

        @Override
        public Optional<O> value() {
            return Optional.of(value);
        }
    }

    final class Identifier<O extends TlsIdentifiable<O, P>, P extends Number> implements TlsIdentifiableUnion<O, P> {
        private final P value;
        private Identifier(P value) {
            this.value = value;
        }

        @Override
        public P id() {
            return value;
        }

        @Override
        public Optional<O> value() {
            return Optional.empty();
        }
    }
}