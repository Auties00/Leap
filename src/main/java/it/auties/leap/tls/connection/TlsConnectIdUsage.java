package it.auties.leap.tls.connection;

import java.util.Arrays;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;

public enum TlsConnectIdUsage {
    CID_IMMEDIATE((byte) 0),
    CID_SPARE((byte) 1);

    private final byte id;
    TlsConnectIdUsage(byte id) {
        this.id = id;
    }

    private static final Map<Byte, TlsConnectIdUsage> VALUES = Arrays.stream(values())
            .collect(Collectors.toUnmodifiableMap(TlsConnectIdUsage::id, Function.identity()));

    public static Optional<TlsConnectIdUsage> of(byte value) {
        return Optional.ofNullable(VALUES.get(value));
    }

    public byte id() {
        return id;
    }
}
