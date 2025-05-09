package it.auties.leap.tls.extension.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsContextualProperty;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.extension.TlsExtensionDependencies;
import it.auties.leap.tls.extension.TlsExtensionPayload;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import static it.auties.leap.tls.extension.TlsExtension.*;
import static it.auties.leap.tls.util.BufferUtils.*;

public sealed class NextProtocolNegotiationExtension {
    public static TlsExtension.Client of() {
        return Client.instance();
    }

    public static TlsExtension.Server of(String selectedProtocol) {
        return new Server(selectedProtocol);
    }

    public Optional<? extends TlsExtension.Server> deserializeClient(TlsContext context, int type, ByteBuffer source) {
        var selectedProtocol = new String(readBytesBigEndian8(source), StandardCharsets.US_ASCII);
        // https://datatracker.ietf.org/doc/html/draft-agl-tls-nextprotoneg-04
        // The padding SHOULD...
        // We ignore the padding check
        source.position(source.limit());
        return Optional.of(new Server(selectedProtocol));
    }

    public Optional<? extends TlsExtension.Client> deserializeServer(TlsContext context, int type, ByteBuffer source) {
        source.position(source.limit());
        return Optional.of(Client.instance());
    }

    public int type() {
        return NEXT_PROTOCOL_NEGOTIATION_TYPE;
    }

    public List<TlsVersion> versions() {
        return NEXT_PROTOCOL_NEGOTIATION_VERSIONS;
    }

    public TlsExtensionDependencies dependencies() {
        return TlsExtensionDependencies.none();
    }

    private static final class Client extends NextProtocolNegotiationExtension implements TlsExtension.Client, TlsExtensionPayload {
        private static final NextProtocolNegotiationExtension.Client INSTANCE = new NextProtocolNegotiationExtension.Client();

        private Client() {

        }

        public static NextProtocolNegotiationExtension.Client instance() {
            return INSTANCE;
        }

        @Override
        public void serializePayload(ByteBuffer buffer) {

        }

        @Override
        public int payloadLength() {
            return 0;
        }

        @Override
        public void apply(TlsContext context, TlsSource source) {

        }

        @Override
        public TlsExtensionPayload toPayload(TlsContext context) {
            return this;
        }

        @Override
        public int hashCode() {
            return type();
        }

        @Override
        public String toString() {
            return "NPNClientExtension[]";
        }
    }

    private static final class Server extends NextProtocolNegotiationExtension implements TlsExtension.Server, TlsExtensionPayload {
        private final String selectedProtocol;

        public Server(
                String selectedProtocol
        ) {
            this.selectedProtocol = selectedProtocol;
        }

        @Override
        public void serializePayload(ByteBuffer buffer) {
            writeBytesBigEndian8(buffer, selectedProtocol.getBytes(StandardCharsets.US_ASCII));
        }

        @Override
        public int payloadLength() {
            return INT8_LENGTH + selectedProtocol.length();
        }

        @Override
        public void apply(TlsContext context, TlsSource source) {
            var connection = switch (source) {
                case LOCAL -> context.localConnectionState();
                case REMOTE -> context.remoteConnectionState()
                        .orElseThrow(() -> new TlsAlert("No remote connection state was created", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR));
            };
            switch (connection.type()) {
                case CLIENT -> context.addAdvertisedValue(TlsContextualProperty.applicationProtocols(), List.of(selectedProtocol));
                case SERVER -> context.addNegotiatedValue(TlsContextualProperty.applicationProtocols(), List.of(selectedProtocol));
            }
        }

        @Override
        public TlsExtensionPayload toPayload(TlsContext context) {
            return this;
        }

        @Override
        public boolean equals(Object o) {
            return o instanceof NextProtocolNegotiationExtension.Server that
                    && Objects.equals(selectedProtocol, that.selectedProtocol);
        }

        @Override
        public int hashCode() {
            return Objects.hashCode(selectedProtocol);
        }

        @Override
        public String toString() {
            return "NPNServerExtension[" +
                    "selectedProtocol=" + selectedProtocol + ']';
        }
    }
}
