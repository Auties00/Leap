package it.auties.leap.tls;

import java.util.Arrays;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;

// https://datatracker.ietf.org/doc/html/rfc8446
public enum TlsPskKeyExchangeMode {
    PSK_KE((byte) 0),
    PSK_DHE_KE((byte) 1);

    private static final Map<Byte, TlsPskKeyExchangeMode> VALUES = Arrays.stream(values())
            .collect(Collectors.toUnmodifiableMap(TlsPskKeyExchangeMode::id, Function.identity()));

    private final byte id;
    TlsPskKeyExchangeMode(byte value) {
        this.id = value;
    }

    public static Optional<TlsPskKeyExchangeMode> of(byte modeId) {
        return Optional.ofNullable(VALUES.get(modeId));
    }

    public byte id() {
        return id;
    }
}
