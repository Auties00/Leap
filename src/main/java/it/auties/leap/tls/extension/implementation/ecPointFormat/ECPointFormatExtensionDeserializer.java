package it.auties.leap.tls.extension.implementation.ecPointFormat;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsContextMode;
import it.auties.leap.tls.ec.TlsECPointFormat;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.extension.TlsExtensionDeserializer;
import it.auties.leap.tls.property.TlsIdentifiableProperty;
import it.auties.leap.tls.property.TlsProperty;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;

import static it.auties.leap.tls.util.BufferUtils.readBigEndianInt8;

final class ECPointFormatExtensionDeserializer implements TlsExtensionDeserializer {
    static final TlsExtensionDeserializer INSTANCE = new ECPointFormatExtensionDeserializer();

    private ECPointFormatExtensionDeserializer() {

    }

    @Override
    public Optional<? extends TlsExtension> deserialize(TlsContext context, int type, ByteBuffer buffer) {
        var ecPointFormatsLength = readBigEndianInt8(buffer);
        var ecPointFormats = new ArrayList<TlsECPointFormat>();
        var knownFormats = context.getNegotiableValue(TlsProperty.ecPointsFormats())
                .orElseThrow(() -> TlsAlert.noNegotiableProperty(TlsProperty.ecPointsFormats()))
                .stream()
                .collect(Collectors.toUnmodifiableMap(TlsIdentifiableProperty::id, Function.identity()));
        var mode = context.selectedMode()
                .orElseThrow(TlsAlert::noModeSelected);
        for(var i = 0; i < ecPointFormatsLength; i++) {
            var ecPointFormatId = readBigEndianInt8(buffer);
            var ecPointFormat = knownFormats.get(ecPointFormatId);
            if(ecPointFormat != null) {
                ecPointFormats.add(ecPointFormat);
            }else if(mode == TlsContextMode.CLIENT) {
                throw new TlsAlert("Remote tried to negotiate an ec point that wasn't advertised");
            }
        }
        var extension = new ECPointFormatExtension(ecPointFormats);
        return Optional.of(extension);
    }
}
