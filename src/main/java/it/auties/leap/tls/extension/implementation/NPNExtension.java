package it.auties.leap.tls.extension.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsContextMode;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.extension.TlsConcreteExtension;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.extension.TlsExtensionDeserializer;
import it.auties.leap.tls.property.TlsProperty;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import static it.auties.leap.tls.util.BufferUtils.*;

public sealed abstract class NPNExtension {
    private static final TlsExtensionDeserializer DECODER = (context, source, _, buffer) -> {
        var mode = context.selectedMode()
                .orElseThrow(TlsAlert::noModeSelected);
        if(mode == TlsContextMode.CLIENT && source == TlsSource.LOCAL || mode == TlsContextMode.SERVER && source == TlsSource.REMOTE) {
            var selectedProtocol = new String(readBytesBigEndian8(buffer), StandardCharsets.US_ASCII);
            // https://datatracker.ietf.org/doc/html/draft-agl-tls-nextprotoneg-04
            // The padding SHOULD...
            // We ignore the padding check
            buffer.position(buffer.limit());
            return Optional.of(new Server(selectedProtocol));
        }else {
            if (buffer.hasRemaining()) {
                throw new TlsAlert("Unexpected extension payload");
            }

            return Optional.of(Client.INSTANCE);
        }
    };

    public static TlsExtension instance() {
        return Client.INSTANCE;
    }

    private static final class Client extends NPNExtension implements TlsConcreteExtension {
        private static final Client INSTANCE = new Client();

        private Client() {

        }

        @Override
        public void serializeExtensionPayload(ByteBuffer buffer) {

        }

        @Override
        public int extensionPayloadLength() {
            return 0;
        }

        @Override
        public void apply(TlsContext context, TlsSource source) {

        }

        @Override
        public int extensionType() {
            return NEXT_PROTOCOL_NEGOTIATION_TYPE;
        }

        @Override
        public List<TlsVersion> versions() {
            return NEXT_PROTOCOL_NEGOTIATION_VERSIONS;
        }

        @Override
        public TlsExtensionDeserializer decoder() {
            return DECODER;
        }

        @Override
        public boolean equals(Object obj) {
            return obj instanceof Client;
        }

        @Override
        public int hashCode() {
            return 1;
        }

        @Override
        public String toString() {
            return "NPNExtension[]";
        }
    }

    private static final class Server extends NPNExtension implements TlsConcreteExtension {
        private final String selectedProtocol;

        private Server(String selectedProtocol) {
            this.selectedProtocol = selectedProtocol;
        }

        @Override
        public void serializeExtensionPayload(ByteBuffer buffer) {
            writeBytesBigEndian8(buffer, selectedProtocol.getBytes(StandardCharsets.US_ASCII));
        }

        @Override
        public int extensionPayloadLength() {
            return INT8_LENGTH + selectedProtocol.length();
        }

        @Override
        public void apply(TlsContext context, TlsSource source) {
            context.addNegotiatedProperty(TlsProperty.applicationProtocols(), List.of(selectedProtocol));
        }

        @Override
        public int extensionType() {
            return NEXT_PROTOCOL_NEGOTIATION_TYPE;
        }

        @Override
        public List<TlsVersion> versions() {
            return NEXT_PROTOCOL_NEGOTIATION_VERSIONS;
        }

        @Override
        public TlsExtensionDeserializer decoder() {
            return DECODER;
        }

        @Override
        public boolean equals(Object o) {
            return o instanceof Server server
                    && Objects.equals(selectedProtocol, server.selectedProtocol);
        }

        @Override
        public int hashCode() {
            return Objects.hashCode(selectedProtocol);
        }

        @Override
        public String toString() {
            return "Server[" +
                    "selectedProtocol=" + selectedProtocol + ']';
        }
    }
}
