package it.auties.leap.socket.tls.extension;

import it.auties.leap.socket.tls.TlsExtension;

public class EncryptThenMacExtension extends TlsExtension {
    public static final TlsExtension INSTANCE = new EncryptThenMacExtension();

    private EncryptThenMacExtension() {

    }

    @Override
    protected int serializeExtensionPayload(byte[] out, int offset) {
        return offset;
    }

    @Override
    public int extensionPayloadLength() {
        return 0;
    }

    @Override
    public int extensionType() {
        return 0x0016;
    }
}
