package it.auties.leap.tls.message;

import java.util.Arrays;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;

public enum TlsMessageContentType {
    CHANGE_CIPHER_SPEC((byte) 20, TlsMessageDeserializer.changeCipherSpec()),
    ALERT((byte) 21, TlsMessageDeserializer.alert()),
    HANDSHAKE((byte) 22, TlsMessageDeserializer.handshake()),
    APPLICATION_DATA((byte) 23, TlsMessageDeserializer.applicationData());

    private static final Map<Byte, TlsMessageContentType> VALUES = Arrays.stream(values())
            .collect(Collectors.toUnmodifiableMap(TlsMessageContentType::id, Function.identity()));

    public static Optional<TlsMessageContentType> of(byte value) {
        return Optional.ofNullable(VALUES.get(value));
    }

    private final byte id;
    private final TlsMessageDeserializer deserializer;

    TlsMessageContentType(byte id, TlsMessageDeserializer deserializer) {
        this.id = id;
        this.deserializer = deserializer;
    }

    public byte id() {
        return id;
    }

    public TlsMessageDeserializer deserializer() {
        return deserializer;
    }
}
