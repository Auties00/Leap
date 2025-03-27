package it.auties.leap.tls.extension.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsContextMode;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.extension.TlsConcreteExtension;
import it.auties.leap.tls.extension.TlsExtensionDeserializer;
import it.auties.leap.tls.property.TlsIdentifiableProperty;
import it.auties.leap.tls.property.TlsProperty;
import it.auties.leap.tls.psk.TlsPSKExchangeMode;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;

import static it.auties.leap.tls.util.BufferUtils.*;

public record PSKExchangeModesExtension(List<TlsPSKExchangeMode> modes) implements TlsConcreteExtension {
    private static final TlsExtensionDeserializer DECODER = (context, source, _, buffer) -> {
        var modesSize = readBigEndianInt16(buffer);
        var modes = new ArrayList<TlsPSKExchangeMode>(modesSize);
        var knownModes = context.getNegotiableValue(TlsProperty.pskExchangeModes())
                .orElseThrow(() -> TlsAlert.noNegotiableProperty(TlsProperty.pskExchangeModes()))
                .stream()
                .collect(Collectors.toUnmodifiableMap(TlsIdentifiableProperty::id, Function.identity()));
        var mode = context.selectedMode()
                .orElseThrow(TlsAlert::noModeSelected);
        var incomingToClient = mode == TlsContextMode.CLIENT && source == TlsSource.REMOTE;
        for(var i = 0; i < modesSize; i++) {
            var pskModeId = readBigEndianInt8(buffer);
            var pskMode = knownModes.get(pskModeId);
            if(pskMode != null) {
                modes.add(pskMode);
            }else if(incomingToClient) {
                throw new TlsAlert("Remote tried to negotiate a psk exchange mode that wasn't advertised");
            }
        }
        var extension = new PSKExchangeModesExtension(modes);
        return Optional.of(extension);
    };

    @Override
    public void serializeExtensionPayload(ByteBuffer buffer) {
        writeBigEndianInt8(buffer, modes.size());
        for (var mode : modes) {
            writeBigEndianInt8(buffer, mode.id());
        }
    }

    @Override
    public int extensionPayloadLength() {
        return INT8_LENGTH + INT8_LENGTH * modes.size();
    }

    @Override
    public void apply(TlsContext context, TlsSource source) {
        switch (source) {
            case LOCAL -> context.addNegotiableProperty(TlsProperty.pskExchangeModes(), modes);
            case REMOTE -> context.addNegotiatedProperty(TlsProperty.pskExchangeModes(), modes);
        }
    }

    @Override
    public int extensionType() {
        return PSK_KEY_EXCHANGE_MODES_TYPE;
    }

    @Override
    public List<TlsVersion> versions() {
        return PSK_KEY_EXCHANGE_MODES_VERSIONS;
    }

    @Override
    public TlsExtensionDeserializer decoder() {
        return DECODER;
    }

    @Override
    public boolean equals(Object obj) {
        return obj instanceof PSKExchangeModesExtension(List<TlsPSKExchangeMode> modes)
                && Objects.equals(this.modes, modes);
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(modes);
    }

    @Override
    public String toString() {
        return "PSKExchangeModesExtension[" +
                "modes=" + modes + ']';
    }
}
