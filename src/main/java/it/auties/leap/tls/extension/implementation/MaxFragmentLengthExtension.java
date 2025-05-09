package it.auties.leap.tls.extension.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
import it.auties.leap.tls.connection.TlsConnectionType;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsContextualProperty;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.extension.TlsExtensionDependencies;
import it.auties.leap.tls.extension.TlsExtensionPayload;
import it.auties.leap.tls.record.TlsMaxFragmentLength;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.Optional;

import static it.auties.leap.tls.util.BufferUtils.*;

public record MaxFragmentLengthExtension(
        TlsMaxFragmentLength maxFragmentLength
) implements TlsExtension.Agnostic, TlsExtensionPayload {
    public MaxFragmentLengthExtension {
        if(maxFragmentLength == null) {
            throw new TlsAlert("Invalid max fragment length", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
        }
    }

    @Override
    public void serializePayload(ByteBuffer buffer) {
        writeBigEndianInt8(buffer, maxFragmentLength.id());
    }

    @Override
    public int payloadLength() {
        return INT8_LENGTH;
    }

    @Override
    public int type() {
        return MAX_FRAGMENT_LENGTH_TYPE;
    }

    @Override
    public TlsExtensionPayload toPayload(TlsContext context) {
        return this;
    }

    @Override
    public Optional<MaxFragmentLengthExtension> deserializeClient(TlsContext context, int type, ByteBuffer source) {
        return deserialize(source);
    }

    @Override
    public Optional<MaxFragmentLengthExtension> deserializeServer(TlsContext context, int type, ByteBuffer source) {
        return deserialize(source);
    }

    private static Optional<MaxFragmentLengthExtension> deserialize(ByteBuffer response) {
        var maxFragmentLengthId = readBigEndianInt8(response);
        var maxFragmentLength = TlsMaxFragmentLength.of(maxFragmentLengthId)
                .orElseThrow(() -> new TlsAlert("Invalid max fragment length id: " + maxFragmentLengthId, TlsAlertLevel.FATAL, TlsAlertType.ILLEGAL_PARAMETER));
        var extension = new MaxFragmentLengthExtension(maxFragmentLength);
        return Optional.of(extension);
    }

    @Override
    public void apply(TlsContext context, TlsSource source) {
        if(source == TlsSource.REMOTE && context.localConnectionState().type() == TlsConnectionType.CLIENT) {
            var advertised = context.getAdvertisedValue(TlsContextualProperty.maxFragmentLength())
                    .orElseThrow(() -> new TlsAlert("Missing negotiable property: maxFragmentLength", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR));
            if(advertised != maxFragmentLength) {
                throw new TlsAlert("Remote tried to negotiate a max fragment length that wasn't advertised", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
            }
        }
        var connection = switch (source) {
            case LOCAL -> context.localConnectionState();
            case REMOTE -> context.remoteConnectionState()
                    .orElseThrow(() -> new TlsAlert("No remote connection state was created", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR));
        };
        switch (connection.type()) {
            case CLIENT -> context.addAdvertisedValue(TlsContextualProperty.maxFragmentLength(), maxFragmentLength);
            case SERVER -> context.addNegotiatedValue(TlsContextualProperty.maxFragmentLength(), maxFragmentLength);
        }
    }

    @Override
    public List<TlsVersion> versions() {
        return MAX_FRAGMENT_LENGTH_VERSIONS;
    }

    @Override
    public TlsExtensionDependencies dependencies() {
        return TlsExtensionDependencies.none();
    }
}
