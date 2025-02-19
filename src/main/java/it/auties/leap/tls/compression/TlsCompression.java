package it.auties.leap.tls.compression;

import it.auties.leap.tls.compression.implementation.Compressions;
import it.auties.leap.tls.compression.implementation.DeflateCompression;
import it.auties.leap.tls.compression.implementation.NoCompression;
import it.auties.leap.tls.compression.implementation.ReservedCompression;

import java.util.List;

public sealed interface TlsCompression extends TlsCompressionHandler permits DeflateCompression, NoCompression, ReservedCompression {
    static TlsCompression none() {
        return NoCompression.instance();
    }

    static TlsCompression deflate() {
        return DeflateCompression.instance();
    }

    static TlsCompression reservedForPrivateUse(byte id) {
        return new ReservedCompression(id, null);
    }

    static TlsCompression reservedForPrivateUse(byte id, TlsCompressionHandler consumer) {
        return new ReservedCompression(id, consumer);
    }

    static List<TlsCompression> allCompressions() {
        return Compressions.values();
    }

    byte id();
}
