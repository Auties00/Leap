package it.auties.leap.socket.tls.extension;

import it.auties.leap.socket.tls.TlsExtension;

public class GreaseExtension extends TlsExtension {
    public static final GreaseExtension[] INSTANCES = new GreaseExtension[]{
            new GreaseExtension(0x0A0A),
            new GreaseExtension(0x1A1A),
            new GreaseExtension(0x2A2A),
            new GreaseExtension(0x3A3A),
            new GreaseExtension(0x4A4A),
            new GreaseExtension(0x5A5A),
            new GreaseExtension(0x6A6A),
            new GreaseExtension(0x7A7A),
            new GreaseExtension(0x8A8A),
            new GreaseExtension(0x9A9A),
            new GreaseExtension(0xAAAA),
            new GreaseExtension(0xBABA),
            new GreaseExtension(0xCACA),
            new GreaseExtension(0xDADA),
            new GreaseExtension(0xEAEA),
            new GreaseExtension(0xFAFA)
    };
    
    private final int extensionType;
    private GreaseExtension(int extensionType) {
        if((extensionType & 0x0f0f) != 0x0a0a) {
            throw new IllegalArgumentException("Invalid grease extension type: " + extensionType);
        }

        this.extensionType = extensionType;
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
        return extensionType;
    }
}
