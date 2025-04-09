package it.auties.leap.tls.extension.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.connection.TlsConnectionType;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.extension.TlsExtensionDependencies;
import it.auties.leap.tls.property.TlsProperty;
import it.auties.leap.tls.record.TlsMaxFragmentLength;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.Optional;

import static it.auties.leap.tls.util.BufferUtils.*;

public record MaxFragmentLengthExtension(
        TlsMaxFragmentLength maxFragmentLength
) implements TlsExtension.Configured.Agnostic {
    public MaxFragmentLengthExtension {
        if(maxFragmentLength == null) {
            throw new TlsAlert("Invalid max fragment length");
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
    public Optional<MaxFragmentLengthExtension> deserialize(TlsContext context, int type, ByteBuffer response) {
        var maxFragmentLengthId = readBigEndianInt8(response);
        var maxFragmentLength = TlsMaxFragmentLength.of(maxFragmentLengthId)
                .orElseThrow(() -> new TlsAlert("Invalid max fragment length id: " + maxFragmentLengthId));
        var extension = new MaxFragmentLengthExtension(maxFragmentLength);
        return Optional.of(extension);
    }

    @Override
    public void apply(TlsContext context, TlsSource source) {
        if(source == TlsSource.REMOTE && context.localConnectionState().type() == TlsConnectionType.CLIENT) {
            var advertised = context.getNegotiableValue(TlsProperty.maxFragmentLength())
                    .orElseThrow(() -> TlsAlert.noNegotiableProperty(TlsProperty.maxFragmentLength()));
            if(advertised != maxFragmentLength) {
                throw new TlsAlert("Remote tried to negotiate a max fragment length that wasn't advertised");
            }
        }
        var connection = switch (source) {
            case LOCAL -> context.localConnectionState();
            case REMOTE -> context.remoteConnectionState()
                    .orElseThrow(TlsAlert::noRemoteConnectionState);
        };
        switch (connection.type()) {
            case CLIENT -> context.addNegotiableProperty(TlsProperty.maxFragmentLength(), maxFragmentLength);
            case SERVER -> context.addNegotiatedProperty(TlsProperty.maxFragmentLength(), maxFragmentLength);
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
