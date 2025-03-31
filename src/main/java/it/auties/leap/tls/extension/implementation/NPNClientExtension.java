package it.auties.leap.tls.extension.implementation;

import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.extension.TlsExtensionDependencies;
import it.auties.leap.tls.extension.TlsExtensionDeserializer;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;

import static it.auties.leap.tls.util.BufferUtils.readBytesBigEndian8;

public record NPNClientExtension(
        
) implements TlsExtension.Configured.Client {
    private static final TlsExtensionDeserializer<TlsExtension.Configured.Server> DESERIALIZER = (_, _, buffer) -> {
        var selectedProtocol = new String(readBytesBigEndian8(buffer), StandardCharsets.US_ASCII);
        // https://datatracker.ietf.org/doc/html/draft-agl-tls-nextprotoneg-04
        // The padding SHOULD...
        // We ignore the padding check
        buffer.position(buffer.limit());
        return Optional.of(new NPNServerExtension(selectedProtocol));
    };
    private static final NPNClientExtension INSTANCE = new NPNClientExtension();

    public static NPNClientExtension instance() {
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
    public int extensionType() {
        return NEXT_PROTOCOL_NEGOTIATION_TYPE;
    }

    @Override
    public List<TlsVersion> versions() {
        return NEXT_PROTOCOL_NEGOTIATION_VERSIONS;
    }

    @Override
    public TlsExtensionDeserializer<? extends TlsExtension.Configured.Server> responseDeserializer() {
        return DESERIALIZER;
    }

    @Override
    public TlsExtensionDependencies dependencies() {
        return TlsExtensionDependencies.none();
    }
}
