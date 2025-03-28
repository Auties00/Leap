package it.auties.leap.tls.extension.implementation.pskExchangeModes;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsContextMode;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.extension.TlsExtensionDeserializer;
import it.auties.leap.tls.property.TlsIdentifiableProperty;
import it.auties.leap.tls.property.TlsProperty;
import it.auties.leap.tls.psk.TlsPSKExchangeMode;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;

import static it.auties.leap.tls.util.BufferUtils.readBigEndianInt16;
import static it.auties.leap.tls.util.BufferUtils.readBigEndianInt8;

final class PSKExchangeModesExtensionDeserializer implements TlsExtensionDeserializer {
    static final TlsExtensionDeserializer INSTANCE = new PSKExchangeModesExtensionDeserializer();

    private PSKExchangeModesExtensionDeserializer() {

    }

    @Override
    public Optional<? extends TlsExtension> deserialize(TlsContext context, int type, ByteBuffer buffer) {
        var modesSize = readBigEndianInt16(buffer);
        var modes = new ArrayList<TlsPSKExchangeMode>(modesSize);
        var knownModes = context.getNegotiableValue(TlsProperty.pskExchangeModes())
                .orElseThrow(() -> TlsAlert.noNegotiableProperty(TlsProperty.pskExchangeModes()))
                .stream()
                .collect(Collectors.toUnmodifiableMap(TlsIdentifiableProperty::id, Function.identity()));
        var mode = context.selectedMode()
                .orElseThrow(TlsAlert::noModeSelected);
        for(var i = 0; i < modesSize; i++) {
            var pskModeId = readBigEndianInt8(buffer);
            var pskMode = knownModes.get(pskModeId);
            if(pskMode != null) {
                modes.add(pskMode);
            }else if(mode == TlsContextMode.CLIENT) {
                throw new TlsAlert("Remote tried to negotiate a psk exchange mode that wasn't advertised");
            }
        }
        var extension = new PSKExchangeModesExtension(modes);
        return Optional.of(extension);
    }
}
