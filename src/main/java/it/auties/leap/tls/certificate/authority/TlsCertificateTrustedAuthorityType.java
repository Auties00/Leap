package it.auties.leap.tls.certificate.authority;

import it.auties.leap.tls.property.TlsIdentifiableProperty;

import java.util.Arrays;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;

public enum TlsCertificateTrustedAuthorityType implements TlsIdentifiableProperty<Byte> {
    PRE_AGREED((byte) 0),
    KEY_SHA1_HASH((byte) 1),
    X509_NAME((byte) 2),
    CERT_SHA1_HASH((byte) 3);

    private static final Map<Byte, TlsCertificateTrustedAuthorityType> VALUES = Arrays.stream(values())
            .collect(Collectors.toUnmodifiableMap(TlsCertificateTrustedAuthorityType::id, Function.identity()));

    private final byte id;

    TlsCertificateTrustedAuthorityType(byte id) {
        this.id = id;
    }

    public static Optional<TlsCertificateTrustedAuthorityType> of(byte id) {
        return Optional.ofNullable(VALUES.get(id));
    }

    @Override
    public Byte id() {
        return id;
    }
}
