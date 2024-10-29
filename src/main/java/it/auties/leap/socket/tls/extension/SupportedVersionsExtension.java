package it.auties.leap.socket.tls.extension;

import it.auties.leap.socket.tls.TlsExtension;

public class SupportedVersionsExtension extends TlsExtension {
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
        return 0x002b;
    }
}
