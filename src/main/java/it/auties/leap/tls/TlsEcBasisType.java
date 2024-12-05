package it.auties.leap.tls;

import java.util.Arrays;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;

public enum TlsEcBasisType {
    TRINOMIAL((byte) 3),
    PENTOMIAL((byte) 5);

    private static final Map<Byte, TlsEcBasisType> VALUES = Arrays.stream(values())
            .collect(Collectors.toUnmodifiableMap(TlsEcBasisType::id, Function.identity()));

    private final byte id;
    TlsEcBasisType(byte id) {
        this.id = id;
    }

    public static Optional<TlsEcBasisType> of(byte value) {
        return Optional.ofNullable(VALUES.get(value));
    }

    public byte id() {
        return id;
    }
}
