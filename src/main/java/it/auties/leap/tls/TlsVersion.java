package it.auties.leap.tls;

import it.auties.leap.socket.SocketProtocol;

import java.util.Arrays;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;

// Implementing a new version is not a supported use case: this is why this class is implemented as an enum
public enum TlsVersion {
    TLS13(0x0304, "TLS1.3", SocketProtocol.TCP),
    TLS12(0x0303, "TLS1.2", SocketProtocol.TCP),
    TLS11(0x0302, "TLS1.1", SocketProtocol.TCP),
    TLS10(0x0301, "TLS1.0", SocketProtocol.TCP),
    SSL30(0x0300, "SSLv3", SocketProtocol.TCP),
    DTLS13(0xFEFC, "DTLS1.3", SocketProtocol.UDP),
    DTLS12(0xFEFD, "DTLS1.2", SocketProtocol.UDP),
    // "There is no DTLS 1.1 because this version-number was skipped in order to harmonize version numbers with TLS"
    DTLS10(0xFEFF, "DTLS1.0", SocketProtocol.UDP);

    private static final Map<String, TlsVersion> NAMES = Arrays.stream(values())
            .collect(Collectors.toUnmodifiableMap(TlsVersion::specName, Function.identity()));
    private static final Map<Integer, TlsVersion> IDS =  Arrays.stream(values())
            .collect(Collectors.toUnmodifiableMap(version -> version.id().value(), Function.identity()));

    public static Optional<TlsVersion> of(String name) {
        return Optional.ofNullable(NAMES.get(name));
    }

    public static Optional<TlsVersion> of(int version) {
        return Optional.ofNullable(IDS.get(version));
    }

    public static Optional<TlsVersion> of(TlsVersionId id) {
        return Optional.ofNullable(IDS.get(id.value()));
    }

    public static Optional<TlsVersion> of(byte major, byte minor) {
        return Optional.ofNullable(IDS.get(TlsVersionId.getId(major, minor)));
    }

    private final TlsVersionId id;
    private final String specName;
    private final SocketProtocol protocol;

    TlsVersion(int id, String specName, SocketProtocol protocol) {
        this.id = new TlsVersionId(id);
        this.specName = specName;
        this.protocol = protocol;
    }

    public TlsVersionId id() {
        return id;
    }

    public String specName() {
        return specName;
    }

    public SocketProtocol protocol() {
        return protocol;
    }
}