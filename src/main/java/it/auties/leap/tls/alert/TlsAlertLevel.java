package it.auties.leap.tls.alert;

import it.auties.leap.tls.property.TlsIdentifiableProperty;

import java.util.Arrays;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;

public enum TlsAlertLevel implements TlsIdentifiableProperty<Byte> {
    WARNING((byte) 1, "warning"),
    FATAL((byte) 2, "fatal");

    private static final Map<Byte, TlsAlertLevel> VALUES = Arrays.stream(values())
            .collect(Collectors.toUnmodifiableMap(TlsAlertLevel::id, Function.identity()));

    private final byte id;
    private final String description;

    TlsAlertLevel(byte id, String description) {
        this.id = id;
        this.description = description;
    }

    public static Optional<TlsAlertLevel> of(byte level) {
        return Optional.ofNullable(VALUES.get(level));
    }

    @Override
    public Byte id() {
        return id;
    }

    public String description() {
        return description;
    }
}
