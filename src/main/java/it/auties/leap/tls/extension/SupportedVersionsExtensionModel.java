package it.auties.leap.tls.extension;

import it.auties.leap.tls.config.TlsGrease;
import it.auties.leap.tls.config.TlsMode;
import it.auties.leap.tls.config.TlsVersion;
import it.auties.leap.tls.config.TlsVersionId;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ThreadLocalRandom;

import static it.auties.leap.tls.util.BufferHelper.*;

final class SupportedVersionsExtensionModel implements TlsExtension.Model {
    static final SupportedVersionsExtensionModel INSTANCE = new SupportedVersionsExtensionModel();
    private SupportedVersionsExtensionModel() {

    }

    @Override
    public Optional<? extends TlsExtension.Implementation> newInstance(Context context) {
        var supportedVersions = new ArrayList<TlsVersionId>();
        var chosenVersion = context.config().version();
        switch (chosenVersion) {
            case TLS13 -> {
                supportedVersions.add(TlsVersion.TLS13.id());
                supportedVersions.add(TlsVersion.TLS12.id());
            }
            case DTLS13 -> {
                supportedVersions.add(TlsVersion.DTLS13.id());
                supportedVersions.add(TlsVersion.DTLS12.id());
            }
            default -> supportedVersions.add(chosenVersion.id());
        }

        if(context.hasExtension(TlsGrease::isGrease)) {
            supportedVersions.add(randomGrease());
        }

        var result = new SupportedVersionsClientExtension(supportedVersions);
        return Optional.of(result);
    }

    @Override
    public Optional<? extends TlsExtension.Implementation> decode(ByteBuffer buffer, int type, TlsMode mode) {
        return switch (mode) {
            case CLIENT -> {
                var payloadSize = readLittleEndianInt8(buffer);
                var versions = new ArrayList<TlsVersionId>();
                try (var _ = scopedRead(buffer, payloadSize)) {
                    var versionsSize = payloadSize / INT16_LENGTH;
                    for (var i = 0; i < versionsSize; i++) {
                        var versionId = TlsVersionId.of(readLittleEndianInt8(buffer), readLittleEndianInt8(buffer));
                        versions.add(versionId);
                    }
                }
                var extension = new SupportedVersionsClientExtension(versions);
                yield Optional.of(extension);
            }
            case SERVER -> {
                var major = readLittleEndianInt8(buffer);
                var minor = readLittleEndianInt8(buffer);
                var versionId = TlsVersionId.of(major, minor);
                var extension = new SupportedVersionsServerExtension(versionId);
                yield Optional.of(extension);
            }
        };
    }

    private static TlsVersionId randomGrease() {
        var grease = TlsVersionId.grease();
        return grease.get(ThreadLocalRandom.current().nextInt(0, grease.size()));
    }

    @Override
    public Class<? extends Implementation> toConcreteType(TlsMode mode) {
        return switch (mode) {
            case CLIENT -> SupportedVersionsClientExtension.class;
            case SERVER -> SupportedVersionsServerExtension.class;
        };
    }

    @Override
    public Dependencies dependencies() {
        return Dependencies.some(GreaseExtension.class);
    }

    @Override
    public int extensionType() {
        return TlsExtensions.SUPPORTED_VERSIONS_TYPE;
    }

    @Override
    public List<TlsVersion> versions() {
        return TlsExtensions.SUPPORTED_VERSIONS_VERSIONS;
    }
}
