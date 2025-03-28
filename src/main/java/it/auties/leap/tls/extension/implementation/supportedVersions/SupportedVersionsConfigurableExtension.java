package it.auties.leap.tls.extension.implementation.supportedVersions;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.cipher.TlsGREASE;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.extension.TlsConfigurableClientExtension;
import it.auties.leap.tls.extension.TlsConfiguredExtension;
import it.auties.leap.tls.extension.TlsExtensionDependencies;
import it.auties.leap.tls.extension.TlsExtensionDeserializer;
import it.auties.leap.tls.property.TlsProperty;
import it.auties.leap.tls.version.TlsVersion;
import it.auties.leap.tls.version.TlsVersionId;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

public final class SupportedVersionsConfigurableExtension implements TlsConfigurableClientExtension {
    private static final SupportedVersionsConfigurableExtension INSTANCE = new SupportedVersionsConfigurableExtension();

    private SupportedVersionsConfigurableExtension() {

    }

    public static SupportedVersionsConfigurableExtension instance() {
        return INSTANCE;
    }

    @Override
    public int extensionType() {
        return SUPPORTED_VERSIONS_TYPE;
    }

    @Override
    public List<TlsVersion> versions() {
        return SUPPORTED_VERSIONS_VERSIONS;
    }

    public TlsExtensionDeserializer deserializer() {
        return SupportedVersionsExtensionDeserializer.INSTANCE;
    }

    @Override
    public Optional<? extends TlsConfiguredExtension> configure(TlsContext context, int messageLength) {
        var mode = context.selectedMode()
                .orElseThrow(TlsAlert::noModeSelected);
        return switch (mode) {
            case CLIENT -> {
                var supportedVersions = new ArrayList<TlsVersionId>();
                context.getNegotiableValue(TlsProperty.version())
                        .orElseThrow(() -> TlsAlert.noNegotiableProperty(TlsProperty.version()))
                        .forEach(version -> supportedVersions.add(version.id()));
                var grease = context.getNegotiableValue(TlsProperty.extensions())
                        .orElseThrow(() -> TlsAlert.noNegotiableProperty(TlsProperty.extensions()))
                        .stream()
                        .anyMatch(entry -> TlsGREASE.isGrease(entry.extensionType()));
                if (grease) {
                    supportedVersions.add(TlsGREASE.greaseRandom());
                }
                yield Optional.of(new SupportedVersionsClientExtension(supportedVersions));
            }
            case SERVER -> {
                var version = context.getNegotiableValue(TlsProperty.version())
                        .orElseThrow(() -> TlsAlert.noNegotiableProperty(TlsProperty.version()))
                        .stream()
                        .reduce((first, second) -> first.id().value() > second.id().value() ? first : second)
                        .orElseThrow(() -> TlsAlert.noNegotiableProperty(TlsProperty.version()));
                yield Optional.of(new SupportedVersionsServerExtension(version));
            }
        };
    }

    @Override
    public TlsExtensionDependencies dependencies() {
        var values = TlsGREASE.values()
                .stream()
                .map(grease -> grease.versionId().value())
                .toArray(Integer[]::new);
        return TlsExtensionDependencies.some(values);
    }
}
