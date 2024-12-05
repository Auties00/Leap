package it.auties.leap.tls;

import java.util.Arrays;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;

// https://www.ietf.org/rfc/rfc4492.txt
public enum TLSEcType {
    EXPLICIT_PRIME((byte) 1),
    EXPLICIT_CHAR2((byte) 2),
    NAMED_CURVE((byte) 3);

    private static final Map<Byte, TLSEcType> VALUES = Arrays.stream(values())
            .collect(Collectors.toUnmodifiableMap(TLSEcType::id, Function.identity()));

    private final byte id;

    TLSEcType(byte id) {
        this.id = id;
    }

    public static Optional<TLSEcType> of(byte id) {
        return Optional.ofNullable(VALUES.get(id));
    }

    public byte id() {
        return id;
    }
}
