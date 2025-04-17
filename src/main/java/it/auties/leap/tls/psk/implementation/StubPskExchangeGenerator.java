package it.auties.leap.tls.psk.implementation;

import it.auties.leap.tls.psk.TlsPskExchangeModeGenerator;
import it.auties.leap.tls.version.TlsVersion;

import java.util.Optional;

public class StubPskExchangeGenerator implements TlsPskExchangeModeGenerator {
    private static final StubPskExchangeGenerator INSTANCE = new StubPskExchangeGenerator();

    private StubPskExchangeGenerator() {

    }

    public static StubPskExchangeGenerator instance() {
        return INSTANCE;
    }

    @Override
    public Optional<byte[]> generate(TlsVersion version) {
        throw new UnsupportedOperationException();
    }
}
