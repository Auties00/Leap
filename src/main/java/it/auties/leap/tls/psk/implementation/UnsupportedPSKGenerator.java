package it.auties.leap.tls.psk.implementation;

import it.auties.leap.tls.psk.TlsPSKExchangeModeGenerator;
import it.auties.leap.tls.version.TlsVersion;

import java.util.Optional;

public final class UnsupportedPSKGenerator implements TlsPSKExchangeModeGenerator {
    private static final UnsupportedPSKGenerator INSTANCE = new UnsupportedPSKGenerator();

    private UnsupportedPSKGenerator() {

    }

    public static UnsupportedPSKGenerator instance() {
        return INSTANCE;
    }

    @Override
    public Optional<byte[]> generate(TlsVersion version) {
        return Optional.empty();
    }
}