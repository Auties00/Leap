package it.auties.leap.tls.extension.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.extension.TlsExtensionDependencies;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.Optional;

import static it.auties.leap.tls.util.BufferUtils.readBigEndianInt8;

public record PaddingExtension(
        int padLength
) implements TlsExtension.Configured.Agnostic {
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
    public int type() {
        return PADDING_TYPE;
    }

    @Override
    public Optional<PaddingExtension> deserialize(TlsContext context, int type, ByteBuffer response) {
        var padLength = readBigEndianInt8(response);
        response.position(response.position() + padLength);
        var extension = new PaddingExtension(padLength);
        return Optional.of(extension);
    }

    @Override
    public void apply(TlsContext context, TlsSource source) {

    }

    @Override
    public List<TlsVersion> versions() {
        return PADDING_VERSIONS;
    }

    @Override
    public TlsExtensionDependencies dependencies() {
        return TlsExtensionDependencies.all();
    }
}
