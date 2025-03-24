package it.auties.leap.tls.message;

import java.util.Arrays;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;

public enum TlsMessageContentType {
    CHANGE_CIPHER_SPEC((byte) 20, "change_cipher_spec"),
    ALERT((byte) 21, "alert"),
    HANDSHAKE((byte) 22, "handshake"),
    APPLICATION_DATA((byte) 23, "application_data");

    private static final Map<Byte, TlsMessageContentType> VALUES = Arrays.stream(values())
            .collect(Collectors.toUnmodifiableMap(TlsMessageContentType::type, Function.identity()));

    public static Optional<TlsMessageContentType> of(byte value) {
        return Optional.ofNullable(VALUES.get(value));
    }

    private final byte type;
    private final String contentName;

    TlsMessageContentType(byte type, String contentName) {
        this.type = type;
        this.contentName = contentName;
    }

    public byte type() {
        return type;
    }

    public String contentName() {
        return contentName;
    }
}
