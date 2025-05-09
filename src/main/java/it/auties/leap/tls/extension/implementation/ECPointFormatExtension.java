package it.auties.leap.tls.extension.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.connection.TlsConnectionType;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.ec.TlsEcPointFormat;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.extension.TlsExtensionDependencies;
import it.auties.leap.tls.context.TlsContextualProperty;
import it.auties.leap.tls.extension.TlsExtensionPayload;
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
) implements TlsExtension.Agnostic, TlsExtensionPayload {
    private static final ECPointFormatExtension ALL = new ECPointFormatExtension(List.of(
            TlsEcPointFormat.uncompressed(),
            TlsEcPointFormat.ansix962CompressedPrime(),
            TlsEcPointFormat.ansix962CompressedChar2()
    ));

    public static TlsExtension.Agnostic all() {
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
            case CLIENT -> context.addAdvertisedValue(TlsContextualProperty.ecPointsFormats(), supportedFormats);
            case SERVER -> context.addNegotiatedValue(TlsContextualProperty.ecPointsFormats(), supportedFormats);
        }
    }

    @Override
    public Optional<ECPointFormatExtension> deserializeClient(TlsContext context, int type, ByteBuffer source) {
        return deserialize(context, source);
    }

    @Override
    public Optional<? extends Client> deserializeServer(TlsContext context, int type, ByteBuffer source) {
        return deserialize(context, source);
    }

    private Optional<ECPointFormatExtension> deserialize(TlsContext context, ByteBuffer response) {
        var ecPointFormatsLength = readBigEndianInt8(response);
        var remoteEcPointFormats = new ArrayList<TlsEcPointFormat>();
        var localEcPointFormats = context.getAdvertisedValue(TlsContextualProperty.ecPointsFormats())
                .orElseThrow(() -> new TlsAlert("Missing negotiable property: ecPointsFormats", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR))
                .stream()
                .collect(Collectors.toUnmodifiableMap(TlsEcPointFormat::id, Function.identity()));
        var mode = context.localConnectionState().type();
        for(var i = 0; i < ecPointFormatsLength; i++) {
            var ecPointFormatId = readBigEndianInt8(response);
            var ecPointFormat = localEcPointFormats.get(ecPointFormatId);
            if(ecPointFormat != null) {
                remoteEcPointFormats.add(ecPointFormat);
            }else if(mode == TlsConnectionType.CLIENT) {
                throw new TlsAlert("Remote tried to negotiate an ec point that wasn't advertised", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
            }
        }
        var extension = new ECPointFormatExtension(remoteEcPointFormats);
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
