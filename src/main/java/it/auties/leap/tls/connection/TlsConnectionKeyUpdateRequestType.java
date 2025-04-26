package it.auties.leap.tls.connection;

import it.auties.leap.tls.property.TlsIdentifiableProperty;

import java.util.Arrays;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;

public enum TlsConnectionKeyUpdateRequestType implements TlsIdentifiableProperty<Byte> {
    UPDATE_NOT_REQUESTED((byte) 0),
    UPDATE_REQUESTED((byte) 1);

    private static final Map<Byte, TlsConnectionKeyUpdateRequestType> VALUES = Arrays.stream(values())
            .collect(Collectors.toUnmodifiableMap(TlsConnectionKeyUpdateRequestType::id, Function.identity()));

    private final byte id;
    TlsConnectionKeyUpdateRequestType(byte id) {
        this.id = id;
    }

    public static Optional<TlsConnectionKeyUpdateRequestType> of(byte level) {
        return Optional.ofNullable(VALUES.get(level));
    }

    @Override
    public Byte id() {
        return id;
    }
}
