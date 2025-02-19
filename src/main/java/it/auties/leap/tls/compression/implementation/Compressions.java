package it.auties.leap.tls.compression.implementation;

import it.auties.leap.tls.compression.TlsCompression;

import java.util.List;

public final class Compressions {
    private static final List<TlsCompression> COMPRESSIONS = List.of(NoCompression.instance(), DeflateCompression.instance());

    public static List<TlsCompression> values() {
        return COMPRESSIONS;
    }
}
