package it.auties.leap.tls.psk;

import it.auties.leap.tls.psk.implementation.UnsupportedPSKGenerator;
import it.auties.leap.tls.version.TlsVersion;

import java.util.Optional;

@FunctionalInterface
public interface TlsPSKExchangeModeGenerator {
    Optional<byte[]> generate(TlsVersion version);

    static TlsPSKExchangeModeGenerator unsupported() {
        return UnsupportedPSKGenerator.instance();
    }
}
