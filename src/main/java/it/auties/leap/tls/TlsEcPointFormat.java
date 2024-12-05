package it.auties.leap.tls;

import java.util.Arrays;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;

public enum TlsEcPointFormat {
    UNCOMPRESSED((byte) 0),
    ANSIX_962_COMPRESSED_PRIME((byte) 1),
    ANSIX_962_COMPRESSED_CHAR_2((byte) 2);

    private static final Map<Byte, TlsEcPointFormat> VALUES = Arrays.stream(values())
            .collect(Collectors.toUnmodifiableMap(TlsEcPointFormat::id, Function.identity()));


    private final byte id;

    TlsEcPointFormat(byte id) {
        this.id = id;
    }

    public static Optional<TlsEcPointFormat> of(byte id) {
        return Optional.ofNullable(VALUES.get(id));
    }

    public byte id() {
        return id;
    }
}
