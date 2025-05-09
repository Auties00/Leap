package it.auties.leap.tls.connection;

import it.auties.leap.tls.hash.TlsHashFactory;
import it.auties.leap.tls.hash.TlsHkdf;
import it.auties.leap.tls.hash.TlsHmac;

import java.nio.ByteBuffer;
import java.util.Arrays;

import static it.auties.leap.tls.util.BufferUtils.*;

public final class TlsConnectionSecret {
    private final byte[] data;
    private boolean destroyed;

    public static TlsConnectionSecret of(byte[] data) {
        return new TlsConnectionSecret(data);
    }

    public static TlsConnectionSecret of(TlsHashFactory hashFactory, String label, byte[] context, byte[] key, int length) {
        var info = createHkdfInfo(label.getBytes(), context, length);
        var hkdf = TlsHkdf.of(TlsHmac.of(hashFactory));
        var data = hkdf.expand(key, info, length);
        return TlsConnectionSecret.of(data);
    }

    private static byte[] createHkdfInfo(byte[] label, byte[] context, int length) {
        var outputLength = INT16_LENGTH
                + INT8_LENGTH + label.length
                + INT8_LENGTH + (context == null ? 0 : context.length);
        var output = ByteBuffer.allocate(outputLength);
        writeBigEndianInt16(output, length);
        writeBytesBigEndian8(output, label);
        if(context == null) {
            writeBigEndianInt8(output, 0x00);
        }else {
            writeBytesBigEndian8(output, context);
        }
        return output.array();
    }

    private TlsConnectionSecret(byte[] data) {
        this.data = data;
    }

    public byte[] data() {
        checkAvailability();
        return data;
    }

    public int length() {
        checkAvailability();
        return data.length;
    }

    public void destroy() {
        destroyed = true;
        Arrays.fill(data, (byte) 0);
    }

    private void checkAvailability() {
        if(destroyed) {
            throw new IllegalStateException("Cannot access a destroyed secret");
        }
    }
}
