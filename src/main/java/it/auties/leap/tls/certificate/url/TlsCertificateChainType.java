package it.auties.leap.tls.certificate.url;

import it.auties.leap.tls.property.TlsIdentifiableProperty;

import java.util.Arrays;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;

public enum TlsCertificateChainType implements TlsIdentifiableProperty<Byte> {
    INDIVIDUAL_CERTS((byte) 0),
    PKIPATH((byte) 1);

    private final byte id;
    TlsCertificateChainType(byte id) {
        this.id = id;
    }

    private static final Map<Byte, TlsCertificateChainType> VALUES = Arrays.stream(values())
            .collect(Collectors.toUnmodifiableMap(TlsCertificateChainType::id, Function.identity()));

    public static Optional<TlsCertificateChainType> of(byte value) {
        return Optional.ofNullable(VALUES.get(value));
    }

    @Override
    public Byte id() {
        return id;
    }
}