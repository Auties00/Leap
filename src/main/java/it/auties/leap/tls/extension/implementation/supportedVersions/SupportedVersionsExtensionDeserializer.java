package it.auties.leap.tls.extension.implementation.supportedVersions;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.extension.TlsExtensionDeserializer;
import it.auties.leap.tls.property.TlsProperty;
import it.auties.leap.tls.version.TlsVersion;
import it.auties.leap.tls.version.TlsVersionId;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;

import static it.auties.leap.tls.util.BufferUtils.*;

final class SupportedVersionsExtensionDeserializer implements TlsExtensionDeserializer {
    static final TlsExtensionDeserializer INSTANCE = new SupportedVersionsExtensionDeserializer();

    private SupportedVersionsExtensionDeserializer() {

    }

    @Override
    public Optional<? extends TlsExtension> deserialize(TlsContext context, int type, ByteBuffer buffer) {
        var mode = context.selectedMode()
                .orElseThrow(TlsAlert::noModeSelected);
        return switch (mode) {
            case CLIENT -> {
                var major = readBigEndianInt8(buffer);
                var minor = readBigEndianInt8(buffer);
                var versionId = TlsVersionId.of(major, minor);
                var supportedVersions = context.getNegotiatedValue(TlsProperty.version())
                        .stream()
                        .collect(Collectors.toUnmodifiableMap(TlsVersion::id, Function.identity()));
                var supportedVersion = supportedVersions.get(versionId);
                if(supportedVersion == null) {
                    throw new TlsAlert("Remote tried to negotiate a version that wasn't advertised");
                }

                var extension = new SupportedVersionsServerExtension(supportedVersion);
                yield Optional.of(extension);
            }

            case SERVER -> {
                var payloadSize = readBigEndianInt8(buffer);
                var versions = new ArrayList<TlsVersionId>();
                try (var _ = scopedRead(buffer, payloadSize)) {
                    var versionsSize = payloadSize / INT16_LENGTH;
                    for (var i = 0; i < versionsSize; i++) {
                        var major = readBigEndianInt8(buffer);
                        var minor = readBigEndianInt8(buffer);
                        var versionId = TlsVersionId.of(major, minor);
                        versions.add(versionId);
                    }
                }
                var extension = new SupportedVersionsClientExtension(versions);
                yield Optional.of(extension);
            }
        };
    }
}
