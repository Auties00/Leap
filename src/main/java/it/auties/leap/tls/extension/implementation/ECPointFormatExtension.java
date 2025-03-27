package it.auties.leap.tls.extension.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsContextMode;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.ec.TlsECPointFormat;
import it.auties.leap.tls.extension.TlsConcreteExtension;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.extension.TlsExtensionDeserializer;
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

public record ECPointFormatExtension(List<TlsECPointFormat> ecPointFormats) implements TlsConcreteExtension {
    private static final ECPointFormatExtension ALL = new ECPointFormatExtension(TlsECPointFormat.values());

    private static final TlsExtensionDeserializer DECODER = (context, source, _, buffer) -> {
        var ecPointFormatsLength = readBigEndianInt8(buffer);
        var ecPointFormats = new ArrayList<TlsECPointFormat>();
        var knownFormats = context.getNegotiableValue(TlsProperty.ecPointsFormats())
                .orElseThrow(() -> TlsAlert.noNegotiableProperty(TlsProperty.ecPointsFormats()))
                .stream()
                .collect(Collectors.toUnmodifiableMap(TlsIdentifiableProperty::id, Function.identity()));
        var mode = context.selectedMode()
                .orElseThrow(TlsAlert::noModeSelected);
        var incomingToClient = mode == TlsContextMode.CLIENT && source == TlsSource.REMOTE;
        for(var i = 0; i < ecPointFormatsLength; i++) {
            var ecPointFormatId = readBigEndianInt8(buffer);
            var ecPointFormat = knownFormats.get(ecPointFormatId);
            if(ecPointFormat != null) {
                ecPointFormats.add(ecPointFormat);
            }else if(incomingToClient) {
                throw new TlsAlert("Remote tried to negotiate an ec point that wasn't advertised");
            }
        }
        var extension = new ECPointFormatExtension(ecPointFormats);
        return Optional.of(extension);
    };

    public static TlsExtension all() {
        return ALL;
    }

    @Override
    public void serializePayload(ByteBuffer buffer) {
        writeBigEndianInt8(buffer, ecPointFormats.size());
        for (var ecPointFormat : ecPointFormats) {
            writeBigEndianInt8(buffer, ecPointFormat.id());
        }
    }

    @Override
    public int payloadLength() {
        return INT8_LENGTH + INT8_LENGTH * ecPointFormats.size();
    }

    @Override
    public void apply(TlsContext context, TlsSource source) {
        switch (source) {
            case LOCAL -> context.addNegotiableProperty(TlsProperty.ecPointsFormats(), ecPointFormats);
            case REMOTE -> context.addNegotiatedProperty(TlsProperty.ecPointsFormats(), ecPointFormats);
        }
    }

    @Override
    public int extensionType() {
        return EC_POINT_FORMATS_TYPE;
    }

    @Override
    public List<TlsVersion> versions() {
        return EC_POINT_FORMATS_VERSIONS;
    }

    @Override
    public TlsExtensionDeserializer decoder() {
        return DECODER;
    }
}
