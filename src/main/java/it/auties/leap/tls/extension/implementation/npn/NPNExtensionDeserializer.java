package it.auties.leap.tls.extension.implementation.npn;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.extension.TlsExtensionDeserializer;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

import static it.auties.leap.tls.util.BufferUtils.readBytesBigEndian8;

final class NPNExtensionDeserializer implements TlsExtensionDeserializer {
    static final NPNExtensionDeserializer INSTANCE = new NPNExtensionDeserializer();

    private NPNExtensionDeserializer() {

    }

    @Override
    public Optional<? extends TlsExtension> deserialize(TlsContext context, int type, ByteBuffer buffer) {
        var mode = context.selectedMode()
                .orElseThrow(TlsAlert::noModeSelected);
        return switch (mode) {
            case CLIENT -> {
                var selectedProtocol = new String(readBytesBigEndian8(buffer), StandardCharsets.US_ASCII);
                // https://datatracker.ietf.org/doc/html/draft-agl-tls-nextprotoneg-04
                // The padding SHOULD...
                // We ignore the padding check
                buffer.position(buffer.limit());
                yield Optional.of(new NPNServerExtension(selectedProtocol));
            }
            case SERVER -> {
                if (buffer.hasRemaining()) {
                    throw new TlsAlert("Unexpected extension payload");
                }

                yield  Optional.of(NPNClientExtension.INSTANCE);
            }
        };
    }
}
