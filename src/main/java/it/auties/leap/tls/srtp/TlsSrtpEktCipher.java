package it.auties.leap.tls.srtp;

import it.auties.leap.tls.property.TlsIdentifiableProperty;

import java.util.Arrays;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;

public enum TlsSrtpEktCipher implements TlsIdentifiableProperty<Byte> {
    RESERVED((byte) 0),
    AESKW_128((byte) 1),
    AESKW_256((byte) 2);

    private static final Map<Byte, TlsSrtpEktCipher> VALUES = Arrays.stream(values())
            .collect(Collectors.toUnmodifiableMap(TlsSrtpEktCipher::id, Function.identity()));

    private final byte id;

    TlsSrtpEktCipher(byte id) {
        this.id = id;
    }

    public static Optional<TlsSrtpEktCipher> of(byte id) {
        return Optional.ofNullable(VALUES.get(id));
    }

    @Override
    public Byte id() {
        return id;
    }
}
