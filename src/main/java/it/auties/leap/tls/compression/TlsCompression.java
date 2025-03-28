package it.auties.leap.tls.compression;

import it.auties.leap.tls.compression.implementation.DeflateCompression;
import it.auties.leap.tls.compression.implementation.NoCompression;
import it.auties.leap.tls.compression.implementation.ReservedCompression;
import it.auties.leap.tls.property.TlsIdentifiableProperty;

import java.nio.ByteBuffer;
import java.util.List;

public sealed interface TlsCompression extends TlsIdentifiableProperty<Byte> permits DeflateCompression, NoCompression, ReservedCompression {
    static TlsCompression none() {
        return NoCompression.instance();
    }

    static TlsCompression deflate() {
        return DeflateCompression.instance();
    }

    static TlsCompression reservedForPrivateUse(byte id) {
        return new ReservedCompression(id, null);
    }

    static TlsCompression reservedForPrivateUse(byte id, TlsCompressor consumer) {
        return new ReservedCompression(id, consumer);
    }

    static List<TlsCompression> values() {
        final class Compressions {
            private static final List<TlsCompression> COMPRESSIONS = List.of(NoCompression.instance(), DeflateCompression.instance());
        }

        return Compressions.COMPRESSIONS;
    }

    static List<TlsCompression> recommended() {
        final class Compressions {
            private static final List<TlsCompression> COMPRESSIONS = List.of(NoCompression.instance());
        }

        return Compressions.COMPRESSIONS;
    }

    void accept(ByteBuffer input, ByteBuffer output, boolean forCompression);
}
