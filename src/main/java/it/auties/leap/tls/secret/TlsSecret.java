package it.auties.leap.tls.secret;

import java.util.Arrays;

public final class TlsSecret {
    private final byte[] data;
    private boolean destroyed;

    public static TlsSecret of(byte[] data) {
        return new TlsSecret(data);
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
