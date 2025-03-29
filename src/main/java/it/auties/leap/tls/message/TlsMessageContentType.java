package it.auties.leap.tls.message;

import it.auties.leap.tls.property.TlsIdentifiableProperty;

import java.util.Arrays;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;

public enum TlsMessageContentType implements TlsIdentifiableProperty<Byte> {
    CHANGE_CIPHER_SPEC((byte) 20),
    ALERT((byte) 21),
    HANDSHAKE((byte) 22),
    APPLICATION_DATA((byte) 23);

    private static final Map<Byte, TlsMessageContentType> VALUES = Arrays.stream(values())
            .collect(Collectors.toUnmodifiableMap(TlsMessageContentType::id, Function.identity()));

    public static Optional<TlsMessageContentType> of(byte value) {
        return Optional.ofNullable(VALUES.get(value));
    }

    private final byte id;

    TlsMessageContentType(byte id) {
        this.id = id;
    }

    @Override
    public Byte id() {
        return id;
    }
}
