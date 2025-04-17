package it.auties.leap.tls.psk;

import it.auties.leap.tls.psk.implementation.DheKePskExchangeGenerator;
import it.auties.leap.tls.psk.implementation.KePskExchangeGenerator;
import it.auties.leap.tls.psk.implementation.StubPskExchangeGenerator;
import it.auties.leap.tls.version.TlsVersion;

import java.util.Optional;

@FunctionalInterface
public interface TlsPskExchangeModeGenerator {
    static TlsPskExchangeModeGenerator ke() {
        return KePskExchangeGenerator.instance();
    }

    static TlsPskExchangeModeGenerator dheKe() {
        return DheKePskExchangeGenerator.instance();
    }

    static TlsPskExchangeModeGenerator stub() {
        return StubPskExchangeGenerator.instance();
    }

    Optional<byte[]> generate(TlsVersion version);
}
