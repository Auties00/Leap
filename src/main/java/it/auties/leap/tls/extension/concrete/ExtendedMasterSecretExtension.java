package it.auties.leap.tls.extension.concrete;

import it.auties.leap.tls.TlsVersion;
import it.auties.leap.tls.extension.TlsConcreteExtension;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.Optional;

public final class ExtendedMasterSecretExtension extends TlsConcreteExtension {
    public static final ExtendedMasterSecretExtension INSTANCE = new ExtendedMasterSecretExtension();
    public static final int EXTENSION_TYPE = 0x0017;

    private ExtendedMasterSecretExtension() {

    }

    public static Optional<ExtendedMasterSecretExtension> of(TlsVersion version, ByteBuffer buffer, int extensionLength) {
        if(extensionLength != 0) {
            throw new IllegalArgumentException("Unexpected extension payload");
        }

        return Optional.of(INSTANCE);
    }

    @Override
    protected void serializeExtensionPayload(ByteBuffer buffer) {

    }

    @Override
    public int extensionPayloadLength() {
        return 0;
    }

    @Override
    public int extensionType() {
        return EXTENSION_TYPE;
    }

    @Override
    public List<TlsVersion> versions() {
        return List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13);
    }
}
