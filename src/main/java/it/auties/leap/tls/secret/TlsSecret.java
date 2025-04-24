package it.auties.leap.tls.secret;

import it.auties.leap.tls.hash.TlsHashFactory;
import it.auties.leap.tls.hash.TlsHkdf;
import it.auties.leap.tls.hash.TlsHmac;

import java.nio.ByteBuffer;
import java.util.Arrays;

import static it.auties.leap.tls.util.BufferUtils.*;

// TODO: Enforce secret destruction
// Currently I'm not enforcing it because during testing it can be annoying
public final class TlsSecret {
    private final byte[] data;
    private boolean destroyed;

    public static TlsSecret of(byte[] data) {
        return new TlsSecret(data);
    }

    public static TlsSecret of(TlsHashFactory hashFactory, String label, byte[] context, byte[] key, int length) {
        var info = createHkdfInfo(label.getBytes(), context, length);
        var hkdf = TlsHkdf.of(TlsHmac.of(hashFactory));
        var data = hkdf.expand(key, info, length);
        System.out.println("______________________________");
        System.out.println("Hash: " + Arrays.toString(context));
        System.out.println("Key: " + Arrays.toString(key));
        System.out.println("Info: " + Arrays.toString(info));
        System.out.println("Result: " + Arrays.toString(data));
        System.out.println("______________________________");
        return TlsSecret.of(data);
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

    private TlsSecret(byte[] data) {
        this.data = data;
    }

    public byte[] data() {
        return data;
    }

    public int length() {
        return data.length;
    }

    public void destroy() {
        destroyed = true;
        Arrays.fill(data, (byte) 0);
    }

}
