package it.auties.leap.tls.name;

import it.auties.leap.tls.util.sun.IPAddressUtil;

import java.util.Map;
import java.util.Optional;
import java.util.function.Predicate;

public enum TlsNameType {
    HOST_NAME((byte) 0, IPAddressUtil::isHostName);

    private static final Map<Byte, TlsNameType> VALUES = Map.of(
            HOST_NAME.id(), HOST_NAME
    );

    public static Optional<TlsNameType> of(byte id) {
        return Optional.ofNullable(VALUES.get(id));
    }

    private final byte id;
    private final Predicate<String> checker;

    TlsNameType(byte id, Predicate<String> checker) {
        this.id = id;
        this.checker = checker;
    }

    public byte id() {
        return id;
    }

    public boolean accepts(String value) {
        return checker.test(value);
    }
}
