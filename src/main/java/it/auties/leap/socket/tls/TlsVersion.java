package it.auties.leap.socket.tls;

import it.auties.leap.socket.SocketProtocol;

import java.util.Map;
import java.util.Objects;
import java.util.Optional;

public enum TlsVersion {
    TLS13(0x0304, "TLS1.3", SocketProtocol.TCP),
    TLS12(0x0303, "TLS1.2", SocketProtocol.TCP),
    TLS11(0x0302, "TLS1.1", SocketProtocol.TCP),
    TLS10(0x0301, "TLS1.0", SocketProtocol.TCP),
    DTLS13(0xFEFC, "DTLS1.3", SocketProtocol.UDP),
    DTLS12(0xFEFD, "DTLS1.2", SocketProtocol.UDP),
    // "There is no DTLS 1.1 because this version-number was skipped in order to harmonize version numbers with TLS"
    DTLS10(0xFEFF, "DTLS1.0", SocketProtocol.UDP);

    private static final Map<String, TlsVersion> VERSIONS;
    static {
        VERSIONS = Map.of(
                TLS13.specName(), TLS13,
                TLS12.specName(), TLS12,
                TLS11.specName(), TLS11,
                TLS10.specName(), TLS10,
                DTLS13.specName(), DTLS13,
                DTLS12.specName(), DTLS12,
                DTLS10.specName(), DTLS10
        );
    }
    
    public static Optional<TlsVersion> of(String name) {
        return Optional.ofNullable(VERSIONS.get(name));
    }

    private final int id;
    private final byte major;
    private final byte minor;
    private final String specName;
    private final SocketProtocol protocol;
    TlsVersion(int id, String specName, SocketProtocol protocol) {
        this.id = id;
        this.major = (byte) ((id >>> 8) & 0xFF);
        this.minor = (byte) (id & 0xFF);
        this.specName = specName;
        this.protocol = protocol;
    }

    public int id() {
        return id;
    }

    public int major() {
        return major;
    }

    public int minor() {
        return minor;
    }

    public String specName() {
        return specName;
    }

    public SocketProtocol protocol() {
        return protocol;
    }
}