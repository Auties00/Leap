package it.auties.leap.tls.secret;

import it.auties.leap.tls.alert.TlsAlert;

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
        if(destroyed) {
            throw TlsAlert.destroyedSecret();
        }

        return data;
    }

    public int length() {
        if(destroyed) {
            throw TlsAlert.destroyedSecret();
        }

        return data.length;
    }

    public void destroy() {
        destroyed = true;
        Arrays.fill(data, (byte) 0);
    }
}
