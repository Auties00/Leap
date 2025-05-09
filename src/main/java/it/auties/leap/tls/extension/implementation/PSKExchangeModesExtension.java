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
import it.auties.leap.tls.psk.TlsPskExchangeMode;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;

import static it.auties.leap.tls.util.BufferUtils.*;

public record PSKExchangeModesExtension(
        List<TlsPskExchangeMode> modes
) implements TlsExtension.Agnostic, TlsExtensionPayload {
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
    public TlsExtensionPayload toPayload(TlsContext context) {
        return this;
    }

    @Override
    public void apply(TlsContext context, TlsSource source) {
        var connection = switch (source) {
            case LOCAL -> context.localConnectionState();
            case REMOTE -> context.remoteConnectionState()
                    .orElseThrow(() -> new TlsAlert("No remote connection state was created", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR));
        };
        switch (connection.type()) {
            case CLIENT -> context.addAdvertisedValue(TlsContextualProperty.pskExchangeModes(), modes);
            case SERVER -> context.addNegotiatedValue(TlsContextualProperty.pskExchangeModes(), modes);
        }
    }

    @Override
    public Optional<PSKExchangeModesExtension> deserializeClient(TlsContext context, int type, ByteBuffer source) {
        return deserialize(context, source);
    }

    @Override
    public Optional<? extends Client> deserializeServer(TlsContext context, int type, ByteBuffer source) {
        return deserialize(context, source);
    }

    private static Optional<PSKExchangeModesExtension> deserialize(TlsContext context, ByteBuffer response) {
        var modesSize = readBigEndianInt16(response);
        var modes = new ArrayList<TlsPskExchangeMode>(modesSize);
        var knownModes = context.getAdvertisedValue(TlsContextualProperty.pskExchangeModes())
                .orElseThrow(() -> new TlsAlert("Missing negotiable property: pskExchangeModes", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR))
                .stream()
                .collect(Collectors.toUnmodifiableMap(TlsPskExchangeMode::id, Function.identity()));
        var mode = context.localConnectionState().type();
        for(var i = 0; i < modesSize; i++) {
            var pskModeId = readBigEndianInt8(response);
            var pskMode = knownModes.get(pskModeId);
            if(pskMode != null) {
                modes.add(pskMode);
            }else if(mode == TlsConnectionType.CLIENT) {
                throw new TlsAlert("Remote tried to negotiate a psk exchange mode that wasn't advertised", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
            }
        }
        var extension = new PSKExchangeModesExtension(modes);
        return Optional.of(extension);
    }

    @Override
    public int type() {
        return PSK_KEY_EXCHANGE_MODES_TYPE;
    }

    @Override
    public List<TlsVersion> versions() {
        return PSK_KEY_EXCHANGE_MODES_VERSIONS;
    }

    @Override
    public TlsExtensionDependencies dependencies() {
        return TlsExtensionDependencies.none();
    }
}
