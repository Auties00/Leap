package it.auties.leap.tls.extension.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.extension.*;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.Optional;

import static it.auties.leap.tls.util.BufferUtils.readBigEndianInt8;

public record PaddingExtension(
        int padLength
) implements TlsExtension.Configured.Agnostic {
    private static final TlsExtensionDeserializer<TlsExtension.Configured.Agnostic> DESERIALIZER = (_, _, buffer) -> {
        var padding = readBigEndianInt8(buffer);
        var extension = new PaddingExtension(padding);
        return Optional.of(extension);
    };

    public PaddingExtension {
        if(padLength < 0) {
            throw new TlsAlert("Invalid negative padding length");
        }
    }

    @Override
    public void serializePayload(ByteBuffer buffer) {
        for (var j = 0; j < padLength; j++) {
            buffer.put((byte) 0);
        }
    }

    @Override
    public int payloadLength() {
        return padLength;
    }

    @Override
    public int extensionType() {
        return PADDING_TYPE;
    }

    @Override
    public void apply(TlsContext context, TlsSource source) {

    }

    @Override
    public List<TlsVersion> versions() {
        return PADDING_VERSIONS;
    }

    @Override
    public TlsExtensionDeserializer<? extends Agnostic> responseDeserializer() {
        return DESERIALIZER;
    }

    @Override
    public TlsExtensionDependencies dependencies() {
        return TlsExtensionDependencies.all();
    }
}
