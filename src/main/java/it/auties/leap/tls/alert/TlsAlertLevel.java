package it.auties.leap.tls.alert;

import java.util.Arrays;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;

public enum TlsAlertLevel {
    WARNING((byte) 1),
    FATAL((byte) 2);

    private static final Map<Byte, TlsAlertLevel> VALUES = Arrays.stream(values())
            .collect(Collectors.toUnmodifiableMap(TlsAlertLevel::id, Function.identity()));

    private final byte id;

    TlsAlertLevel(byte id) {
        this.id = id;
    }

    public static Optional<TlsAlertLevel> of(byte level) {
        return Optional.ofNullable(VALUES.get(level));
    }

    public byte id() {
        return id;
    }
}
