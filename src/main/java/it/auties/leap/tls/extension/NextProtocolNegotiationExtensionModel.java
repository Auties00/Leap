package it.auties.leap.tls.extension;

import it.auties.leap.tls.config.TlsMode;
import it.auties.leap.tls.config.TlsVersion;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.Optional;

import static it.auties.leap.tls.util.BufferHelper.readBytesLittleEndian8;

final class NextProtocolNegotiationExtensionModel implements TlsExtension.Model {
    @Override
    public Optional<? extends Implementation> newInstance(Context context) {
        return Optional.empty();
    }

    @Override
    public Optional<? extends Implementation> decode(ByteBuffer buffer, int type, TlsMode mode) {
        return switch (mode) {
            case CLIENT -> {
                if (buffer.hasRemaining()) {
                    throw new IllegalArgumentException("Unexpected extension payload");
                }

                yield Optional.of(NextProtocolNegotiationClientExtension.INSTANCE);
            }
            case SERVER -> {
                var selectedProtocol = readBytesLittleEndian8(buffer);
                var extension = new NextProtocolNegotiationServerExtension(selectedProtocol);
                yield Optional.of(extension);
            }
        };
    }

    @Override
    public Class<? extends Implementation> toConcreteType(TlsMode mode) {
        return switch (mode) {
            case CLIENT -> NextProtocolNegotiationClientExtension.class;
            case SERVER -> NextProtocolNegotiationServerExtension.class;
        };
    }

    @Override
    public Dependencies dependencies() {
        return Dependencies.none();
    }

    @Override
    public int extensionType() {
        return TlsExtensions.NEXT_PROTOCOL_NEGOTIATION_TYPE;
    }

    @Override
    public List<TlsVersion> versions() {
        return TlsExtensions.NEXT_PROTOCOL_NEGOTIATION_VERSIONS;
    }
}
