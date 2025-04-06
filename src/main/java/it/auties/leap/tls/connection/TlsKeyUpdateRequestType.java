package it.auties.leap.tls.connection;

import it.auties.leap.tls.property.TlsIdentifiableProperty;

import java.util.Arrays;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;

public enum TlsKeyUpdateRequestType implements TlsIdentifiableProperty<Byte> {
    UPDATE_NOT_REQUESTED((byte) 0),
    UPDATE_REQUESTED((byte) 1);

    private static final Map<Byte, TlsKeyUpdateRequestType> VALUES = Arrays.stream(values())
            .collect(Collectors.toUnmodifiableMap(TlsKeyUpdateRequestType::id, Function.identity()));

    private final byte id;
    TlsKeyUpdateRequestType(byte id) {
        this.id = id;
    }

    public static Optional<TlsKeyUpdateRequestType> of(byte level) {
        return Optional.ofNullable(VALUES.get(level));
    }

    @Override
    public Byte id() {
        return id;
    }
}
