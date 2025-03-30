package it.auties.leap.tls.extension.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsContextMode;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.extension.*;
import it.auties.leap.tls.property.TlsIdentifiableProperty;
import it.auties.leap.tls.property.TlsProperty;
import it.auties.leap.tls.psk.TlsPSKExchangeMode;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;

import static it.auties.leap.tls.util.BufferUtils.*;
import static it.auties.leap.tls.util.BufferUtils.readBigEndianInt8;

public record PSKExchangeModesExtension(
        List<TlsPSKExchangeMode> modes
) implements TlsExtension.Configured.Agnostic {
    private static final TlsExtensionDeserializer<TlsExtension.Configured.Agnostic> DESERIALIZER = (context, _, buffer) -> {
        var modesSize = readBigEndianInt16(buffer);
        var modes = new ArrayList<TlsPSKExchangeMode>(modesSize);
        var knownModes = context.getNegotiableValue(TlsProperty.pskExchangeModes())
                .orElseThrow(() -> TlsAlert.noNegotiableProperty(TlsProperty.pskExchangeModes()))
                .stream()
                .collect(Collectors.toUnmodifiableMap(TlsIdentifiableProperty::id, Function.identity()));
        var mode = context.selectedMode();
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
    };

    @Override
    public void serializePayload(ByteBuffer buffer) {
        writeBigEndianInt8(buffer, modes.size());
        for (var mode : modes) {
            writeBigEndianInt8(buffer, mode.id());
        }
    }

    @Override
    public int payloadLength() {
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
    public TlsExtensionDeserializer<? extends TlsExtension.Configured.Client> clientDeserializer() {
        return DESERIALIZER;
    }

    @Override
    public TlsExtensionDeserializer<? extends TlsExtension.Configured.Server> serverDeserializer() {
        return DESERIALIZER;
    }


    @Override
    public TlsExtensionDependencies dependencies() {
        return TlsExtensionDependencies.none();
    }
}
