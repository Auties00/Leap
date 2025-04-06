package it.auties.leap.tls.extension.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.connection.TlsConnectionType;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.ec.TlsEcPointFormat;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.extension.TlsExtensionDependencies;
import it.auties.leap.tls.property.TlsIdentifiableProperty;
import it.auties.leap.tls.property.TlsProperty;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;

import static it.auties.leap.tls.util.BufferUtils.*;

public record ECPointFormatExtension(
        List<TlsEcPointFormat> supportedFormats
) implements TlsExtension.Configured.Agnostic {
    private static final ECPointFormatExtension ALL = new ECPointFormatExtension(TlsEcPointFormat.values());

    public static TlsExtension.Configured.Agnostic all() {
        return ALL;
    }

    @Override
    public void serializePayload(ByteBuffer buffer) {
        writeBigEndianInt8(buffer, supportedFormats.size());
        for (var ecPointFormat : supportedFormats) {
            writeBigEndianInt8(buffer, ecPointFormat.id());
        }
    }

    @Override
    public int payloadLength() {
        return INT8_LENGTH + INT8_LENGTH * supportedFormats.size();
    }

    @Override
    public void apply(TlsContext context, TlsSource source) {
        switch (source) {
            case LOCAL -> context.addNegotiableProperty(TlsProperty.ecPointsFormats(), supportedFormats);
            case REMOTE -> context.addNegotiatedProperty(TlsProperty.ecPointsFormats(), supportedFormats);
        }
    }

    @Override
    public Optional<ECPointFormatExtension> deserialize(TlsContext context, int type, ByteBuffer buffer) {
        var ecPointFormatsLength = readBigEndianInt8(buffer);
        var ecPointFormats = new ArrayList<TlsEcPointFormat>();
        var knownFormats = context.getNegotiableValue(TlsProperty.ecPointsFormats())
                .orElseThrow(() -> TlsAlert.noNegotiableProperty(TlsProperty.ecPointsFormats()))
                .stream()
                .collect(Collectors.toUnmodifiableMap(TlsIdentifiableProperty::id, Function.identity()));
        var mode = context.localConnectionState().type();
        for(var i = 0; i < ecPointFormatsLength; i++) {
            var ecPointFormatId = readBigEndianInt8(buffer);
            var ecPointFormat = knownFormats.get(ecPointFormatId);
            if(ecPointFormat != null) {
                ecPointFormats.add(ecPointFormat);
            }else if(mode == TlsConnectionType.CLIENT) {
                throw new TlsAlert("Remote tried to negotiate an ec point that wasn't advertised");
            }
        }
        var extension = new ECPointFormatExtension(ecPointFormats);
        return Optional.of(extension);
    }

    @Override
    public int type() {
        return EC_POINT_FORMATS_TYPE;
    }

    @Override
    public List<TlsVersion> versions() {
        return EC_POINT_FORMATS_VERSIONS;
    }

    @Override
    public TlsExtensionDependencies dependencies() {
        return TlsExtensionDependencies.none();
    }
}
