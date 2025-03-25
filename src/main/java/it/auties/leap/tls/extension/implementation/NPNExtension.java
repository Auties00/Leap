package it.auties.leap.tls.extension.implementation;

import it.auties.leap.tls.TlsContext;
import it.auties.leap.tls.TlsSource;
import it.auties.leap.tls.TlsException;
import it.auties.leap.tls.extension.TlsExtension.Concrete;
import it.auties.leap.tls.extension.TlsExtensionDeserializer;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static it.auties.leap.tls.util.BufferUtils.*;
import static it.auties.leap.tls.util.BufferUtils.writeBytesBigEndian8;

public abstract sealed class NPNExtension {
    private static final TlsExtensionDeserializer DECODER = new TlsExtensionDeserializer() {
        @Override
        public Optional<? extends Concrete> deserialize(TlsContext context, TlsSource source, int type, ByteBuffer buffer) {
            return switch (context.selectedMode().orElse(null)) {
                case CLIENT -> switch (source) {
                    case LOCAL -> deserializeClient(buffer);
                    case REMOTE -> deserializeServer(buffer);
                };
                case SERVER ->  switch (source) {
                    case REMOTE -> deserializeClient(buffer);
                    case LOCAL -> deserializeServer(buffer);
                };
                case null -> throw new TlsException("No mode was selected yet");
            };
        }

        private Optional<Server> deserializeServer(ByteBuffer buffer) {
            var selectedProtocol = readBytesBigEndian8(buffer);
            // https://datatracker.ietf.org/doc/html/draft-agl-tls-nextprotoneg-04
            // The padding SHOULD...
            // We ignore the padding check
            buffer.position(buffer.limit());
            return Optional.of(new Server(selectedProtocol));
        }

        private Optional<Client> deserializeClient(ByteBuffer buffer) {
            if (buffer.hasRemaining()) {
                throw new IllegalArgumentException("Unexpected extension payload");
            }

            return Optional.of(Client.instance());
        }
    };

    private NPNExtension() {

    }

    public static final class Client extends NPNExtension implements Concrete {
        private static final Client INSTANCE = new Client();
        private Client() {

        }

        public static Client instance() {
            return INSTANCE;
        }

        @Override
        public void serializeExtensionPayload(ByteBuffer buffer) {

        }

        @Override
        public int extensionPayloadLength() {
            return 0;
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
            return obj == this || obj != null && obj.getClass() == this.getClass();
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

    public static final class Server extends NPNExtension implements Concrete {
        private final byte[] selectedProtocol;
        public Server(byte[] selectedProtocol) {
            assertBytesBigEndian8(selectedProtocol);
            this.selectedProtocol = selectedProtocol;
        }

        @Override
        public void serializeExtensionPayload(ByteBuffer buffer) {
            writeBytesBigEndian8(buffer, selectedProtocol);
        }

        @Override
        public int extensionPayloadLength() {
            return INT8_LENGTH + selectedProtocol.length
                    + (32 - ((selectedProtocol.length + 2) % 32));
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
        public String toString() {
            return "NPNExtension[" +
                    "selectedProtocol=" + new String(selectedProtocol, StandardCharsets.US_ASCII) +
                    ']';
        }

        public byte[] selectedProtocol() {
            return selectedProtocol;
        }

        @Override
        public boolean equals(Object obj) {
            if (obj == this) return true;
            if (obj == null || obj.getClass() != this.getClass()) return false;
            var that = (Server) obj;
            return Arrays.equals(this.selectedProtocol, that.selectedProtocol);
        }

        @Override
        public int hashCode() {
            return Arrays.hashCode(selectedProtocol);
        }
    }
}
