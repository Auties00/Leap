package it.auties.leap.tls;

import java.util.Arrays;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;

public enum TlsClientCertificateType {
    RSA_SIGN((byte) 1),
    DSS_SIGN((byte) 2),
    RSA_FIXED_DH((byte) 3),
    DSS_FIXED_DH((byte) 4),
    RSA_EPHEMERAL_DH((byte) 5),
    DSS_EPHEMERAL_DH((byte) 6),
    FORTEZZA_DMS((byte) 20),
    ECDSA_SIGN((byte) 64),
    RSA_FIXED_ECDH((byte) 65),
    ECDSA_FIXED_ECDH((byte) 66),
    FALCON_SIGN((byte) 67),
    DILITHIUM_SIGN((byte) 68);

    private static final Map<Byte, TlsClientCertificateType> VALUES = Arrays.stream(values())
            .collect(Collectors.toUnmodifiableMap(TlsClientCertificateType::id, Function.identity()));

    private final byte id;
    TlsClientCertificateType(byte id) {
        this.id = id;
    }

    public static Optional<TlsClientCertificateType> of(byte id) {
        return Optional.ofNullable(VALUES.get(id));
    }

    public byte id() {
        return id;
    }
}
