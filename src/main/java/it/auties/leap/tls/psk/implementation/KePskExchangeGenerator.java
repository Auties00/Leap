package it.auties.leap.tls.psk.implementation;

import it.auties.leap.tls.psk.TlsPskExchangeModeGenerator;
import it.auties.leap.tls.version.TlsVersion;

import java.util.Optional;

public class KePskExchangeGenerator implements TlsPskExchangeModeGenerator {
    private static final KePskExchangeGenerator INSTANCE = new KePskExchangeGenerator();

    private KePskExchangeGenerator() {

    }

    public static KePskExchangeGenerator instance() {
        return INSTANCE;
    }

    @Override
    public Optional<byte[]> generate(TlsVersion version) {
        throw new UnsupportedOperationException();
    }
}
