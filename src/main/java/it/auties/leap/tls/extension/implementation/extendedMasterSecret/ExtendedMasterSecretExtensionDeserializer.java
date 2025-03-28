package it.auties.leap.tls.extension.implementation.extendedMasterSecret;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.extension.TlsExtensionDeserializer;
import it.auties.leap.tls.extension.implementation.encryptThenMac.EncryptThenMacExtension;

import java.nio.ByteBuffer;
import java.util.Optional;

final class ExtendedMasterSecretExtensionDeserializer implements TlsExtensionDeserializer {
    static final TlsExtensionDeserializer INSTANCE = new ExtendedMasterSecretExtensionDeserializer();

    private ExtendedMasterSecretExtensionDeserializer() {

    }

    @Override
    public Optional<? extends TlsExtension> deserialize(TlsContext context, int type, ByteBuffer buffer) {
        if (buffer.hasRemaining()) {
            throw new TlsAlert("Unexpected extension payload");
        }

        return Optional.of(ExtendedMasterSecretExtension.INSTANCE);
    }
}
