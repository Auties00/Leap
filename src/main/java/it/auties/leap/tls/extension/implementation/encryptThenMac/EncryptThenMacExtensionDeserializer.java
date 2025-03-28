package it.auties.leap.tls.extension.implementation.encryptThenMac;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.extension.TlsExtensionDeserializer;

import java.nio.ByteBuffer;
import java.util.Optional;

final class EncryptThenMacExtensionDeserializer implements TlsExtensionDeserializer {
    static final TlsExtensionDeserializer INSTANCE = new EncryptThenMacExtensionDeserializer();

    private EncryptThenMacExtensionDeserializer() {

    }

    @Override
    public Optional<? extends TlsExtension> deserialize(TlsContext context, int type, ByteBuffer buffer) {
        if (buffer.hasRemaining()) {
            throw new TlsAlert("Unexpected extension payload");
        }

        return Optional.of(EncryptThenMacExtension.INSTANCE);
    }
}
