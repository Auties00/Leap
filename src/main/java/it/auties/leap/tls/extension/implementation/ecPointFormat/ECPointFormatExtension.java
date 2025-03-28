package it.auties.leap.tls.extension.implementation.ecPointFormat;

import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.ec.TlsECPointFormat;
import it.auties.leap.tls.extension.*;
import it.auties.leap.tls.property.TlsProperty;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;
import java.util.List;

import static it.auties.leap.tls.util.BufferUtils.INT8_LENGTH;
import static it.auties.leap.tls.util.BufferUtils.writeBigEndianInt8;

public record ECPointFormatExtension(
        List<TlsECPointFormat> supportedFormats
) implements TlsConfiguredClientExtension, TlsConfiguredServerExtension  {
    private static final ECPointFormatExtension ALL = new ECPointFormatExtension(TlsECPointFormat.values());

    public static TlsExtension all() {
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
    public int extensionType() {
        return EC_POINT_FORMATS_TYPE;
    }

    @Override
    public List<TlsVersion> versions() {
        return EC_POINT_FORMATS_VERSIONS;
    }

    @Override
    public TlsExtensionDeserializer deserializer() {
        return ECPointFormatExtensionDeserializer.INSTANCE;
    }

    @Override
    public TlsExtensionDependencies dependencies() {
        return TlsExtensionDependencies.none();
    }
}
