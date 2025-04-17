package it.auties.leap.tls.psk.implementation;

import it.auties.leap.tls.psk.TlsPskExchangeModeGenerator;
import it.auties.leap.tls.version.TlsVersion;

import java.util.Optional;

public class DheKePskExchangeGenerator implements TlsPskExchangeModeGenerator {
    private static final DheKePskExchangeGenerator INSTANCE = new DheKePskExchangeGenerator();

    private DheKePskExchangeGenerator() {

    }

    public static DheKePskExchangeGenerator instance() {
        return INSTANCE;
    }

    @Override
    public Optional<byte[]> generate(TlsVersion version) {
        throw new UnsupportedOperationException();
    }
}
