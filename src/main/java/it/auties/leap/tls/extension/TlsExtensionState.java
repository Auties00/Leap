package it.auties.leap.tls.extension;

import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;

import java.nio.ByteBuffer;
import java.util.Optional;

import static it.auties.leap.tls.util.BufferUtils.INT16_LENGTH;
import static it.auties.leap.tls.util.BufferUtils.writeBigEndianInt16;

public sealed interface TlsExtensionState extends TlsExtensionMetadataProvider {
    sealed interface Configurable extends TlsExtensionState permits TlsExtension.Configurable {
        Optional<? extends TlsExtension.Configured.Client> configureClient(TlsContext context, int messageLength);
        Optional<? extends TlsExtension.Configured.Server> configureServer(TlsContext context, int messageLength);
    }

    sealed interface Configured extends TlsExtensionState permits TlsExtension.Configured {
        void apply(TlsContext context, TlsSource source);
        Optional<? extends TlsExtension.Configured> deserialize(TlsContext context, int type, ByteBuffer response);

        default void serialize(ByteBuffer buffer) {
            writeBigEndianInt16(buffer, type());
            writeBigEndianInt16(buffer, payloadLength());
            serializePayload(buffer);
        }

        default int headerLength() {
            return INT16_LENGTH + INT16_LENGTH;
        }

        default int length() {
            return headerLength() + payloadLength();
        }

        void serializePayload(ByteBuffer buffer);
        int payloadLength();
    }
}
