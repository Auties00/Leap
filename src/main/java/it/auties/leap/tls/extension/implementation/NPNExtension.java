package it.auties.leap.tls.extension.implementation;

import it.auties.leap.tls.context.TlsMode;
import it.auties.leap.tls.extension.TlsExtension.Concrete;
import it.auties.leap.tls.extension.TlsExtensionDeserializer;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static it.auties.leap.tls.util.BufferUtils.*;

public abstract sealed class NPNExtension {
    private static final TlsExtensionDeserializer DECODER = new TlsExtensionDeserializer() {
        @Override
        public Optional<? extends Concrete> deserialize(ByteBuffer buffer, int type, TlsMode mode) {
            return switch (mode) {
                case CLIENT -> {
                    if (buffer.hasRemaining()) {
                        throw new IllegalArgumentException("Unexpected extension payload");
                    }

                    yield Optional.of(Client.instance());
                }
                case SERVER -> {
                    var selectedProtocol = readBytesBigEndian8(buffer);
                    yield Optional.of(new Server(selectedProtocol));
                }
            };
        }

        @Override
        public Class<? extends Concrete> toConcreteType(TlsMode mode) {
            return switch (mode) {
                case CLIENT -> Client.class;
                case SERVER -> Server.class;
            };
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
            this.selectedProtocol = selectedProtocol;
        }

        public static Server of(String selectedProtocol) {
            return new Server(selectedProtocol.getBytes(StandardCharsets.US_ASCII));
        }

        @Override
        public void serializeExtensionPayload(ByteBuffer buffer) {
            writeBytesBigEndian8(buffer, selectedProtocol);
        }

        @Override
        public int extensionPayloadLength() {
            return INT8_LENGTH + selectedProtocol.length;
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
