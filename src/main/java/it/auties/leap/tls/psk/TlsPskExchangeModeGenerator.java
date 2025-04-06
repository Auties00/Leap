package it.auties.leap.tls.psk;

import it.auties.leap.tls.version.TlsVersion;

import java.util.Optional;

@FunctionalInterface
public interface TlsPskExchangeModeGenerator {
    Optional<byte[]> generate(TlsVersion version);
}
