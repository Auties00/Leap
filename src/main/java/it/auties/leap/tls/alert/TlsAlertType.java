package it.auties.leap.tls.alert;

import java.util.Arrays;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;

public enum TlsAlertType {
    CLOSE_NOTIFY((byte) 0),
    UNEXPECTED_MESSAGE((byte) 10),
    BAD_RECORD_MAC((byte) 20),
    DECRYPTION_FAILED((byte) 21),
    RECORD_OVERFLOW((byte) 22),
    DECOMPRESSION_FAILURE((byte) 30),
    HANDSHAKE_FAILURE((byte) 40),
    NO_CERTIFICATE((byte) 41),
    BAD_CERTIFICATE((byte) 42),
    UNSUPPORTED_CERTIFICATE((byte) 43),
    CERTIFICATE_REVOKED((byte) 44),
    CERTIFICATE_EXPIRED((byte) 45),
    CERTIFICATE_UNKNOWN((byte) 46),
    ILLEGAL_PARAMETER((byte) 47),
    UNKNOWN_CA((byte) 48),
    ACCESS_DENIED((byte) 49),
    DECODE_ERROR((byte) 50),
    DECRYPT_ERROR((byte) 51),
    EXPORT_RESTRICTION((byte) 60),
    PROTOCOL_VERSION((byte) 70),
    INSUFFICIENT_SECURITY((byte) 71),
    INTERNAL_ERROR((byte) 80),
    INAPPROPRIATE_FALLBACK((byte) 86),
    USER_CANCELED((byte) 90),
    NO_RENEGOTIATION((byte) 100),
    MISSING_EXTENSION((byte) 109),
    UNSUPPORTED_EXTENSION((byte) 110),
    CERTIFICATE_UNOBTAINABLE((byte) 111),
    UNRECOGNIZED_NAME((byte) 112),
    BAD_CERT_STATUS_RESPONSE((byte) 113),
    BAD_CERT_HASH_VALUE((byte) 114),
    UNKNOWN_PSK_IDENTITY((byte) 115),
    CERTIFICATE_REQUIRED((byte) 116),
    NO_APPLICATION_PROTOCOL((byte) 120);

    private static final Map<Byte, TlsAlertType> VALUES = Arrays.stream(values())
            .collect(Collectors.toUnmodifiableMap(TlsAlertType::id, Function.identity()));

    private final byte id;

    TlsAlertType(byte id) {
        this.id = id;
    }

    public static Optional<TlsAlertType> of(byte id) {
        return Optional.ofNullable(VALUES.get(id));
    }

    public byte id() {
        return id;
    }
}
