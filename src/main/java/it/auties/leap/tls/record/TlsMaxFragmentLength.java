package it.auties.leap.tls.record;

import java.util.Arrays;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;

public enum TlsMaxFragmentLength {
    TWO_TO_THE_NINTH((byte) 1),
    TWO_TO_THE_TENTH((byte) 2),
    TWO_TO_THE_ELEVENTH((byte) 3),
    TWO_TO_THE_TWELFTH((byte) 4);

    private static final Map<Byte, TlsMaxFragmentLength> VALUES = Arrays.stream(values())
            .collect(Collectors.toUnmodifiableMap(TlsMaxFragmentLength::id, Function.identity()));

    private final byte id;

    TlsMaxFragmentLength(byte id) {
        this.id = id;
    }

    public static Optional<TlsMaxFragmentLength> of(byte id) {
        return Optional.ofNullable(VALUES.get(id));
    }

    public byte id() {
        return id;
    }
}
