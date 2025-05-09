package it.auties.leap.tls.srtp;

import java.util.Arrays;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;

public enum SrtpEktCipher {
    RESERVED((byte) 0),
    AESKW_128((byte) 1),
    AESKW_256((byte) 2);

    private static final Map<Byte, SrtpEktCipher> VALUES = Arrays.stream(values())
            .collect(Collectors.toUnmodifiableMap(SrtpEktCipher::id, Function.identity()));

    private final byte id;

    SrtpEktCipher(byte id) {
        this.id = id;
    }

    public static Optional<SrtpEktCipher> of(byte id) {
        return Optional.ofNullable(VALUES.get(id));
    }

    public byte id() {
        return id;
    }
}
