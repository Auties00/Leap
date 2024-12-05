package it.auties.leap.tls.engine;

import it.auties.leap.tls.TlsExtension;
import it.auties.leap.tls.TlsSupportedGroup;
import it.auties.leap.tls.TlsVersion;
import it.auties.leap.tls.TlsVersionId;
import it.auties.leap.tls.extension.TlsConcreteExtension;
import it.auties.leap.tls.extension.TlsModelExtension;
import it.auties.leap.tls.extension.TlsModelExtension.Dependencies;
import it.auties.leap.tls.extension.TlsModelExtension.Dependencies.Some;
import it.auties.leap.tls.extension.concrete.*;
import it.auties.leap.tls.extension.model.ClientSupportedVersionsModel;
import it.auties.leap.tls.extension.model.KeyShareExtensionModel;
import it.auties.leap.tls.extension.model.PaddingExtensionModel;
import it.auties.leap.tls.extension.model.SNIExtensionModel;
import it.auties.leap.tls.message.TlsMessage;
import it.auties.leap.tls.message.TlsHandshakeMessage;
import it.auties.leap.tls.message.client.ClientHelloMessage;

import java.net.InetSocketAddress;
import java.util.*;

import static it.auties.leap.tls.TlsRecord.INT16_LENGTH;

public class TlsExtensionsProcessor {
    private final TlsEngine tlsEngine;
    private final Map<Class<? extends TlsExtension>, Dependencies> dependenciesTree;
    private final List<List<TlsExtension>> rounds;
    private final List<TlsConcreteExtension> processedExtensions;
    private int processedExtensionsLength;
    private List<TlsSupportedGroup> supportedGroups;
    private boolean extendedMasterSecret;
    private boolean explicitVersionsSupport;
    private boolean greaseSupport;
    public TlsExtensionsProcessor(TlsEngine tlsEngine) {
        // Set the tls engine
        this.tlsEngine = tlsEngine;

        // Find all compatible extensions
        var compatibleExtensions = tlsEngine.config()
                .extensions()
                .stream()
                .filter(extension -> extension.versions().contains(tlsEngine.config().version()))
                .toList();

        // Make sure there are no conflicts
        this.dependenciesTree = new HashMap<>();
        for (var extension : compatibleExtensions) {
            switch (extension) {
                case TlsConcreteExtension concreteExtension -> {
                    if (dependenciesTree.put(concreteExtension.getClass(), Dependencies.none()) != null) {
                        throw new IllegalArgumentException("Extension with type %s conflicts with previously defined extension".formatted(extension.getClass().getName()));
                    }
                }
                case TlsModelExtension<?, ?> modelExtension -> {
                    if (dependenciesTree.put(modelExtension.getClass(), modelExtension.dependencies()) != null) {
                        throw new IllegalArgumentException("Extension with type %s, which produces %s, conflicts with previously defined extension".formatted(modelExtension.getClass().getName(), modelExtension.resultType().getName()));
                    }
                }
            }
        }

        // Allocate the rounds and fill them
        this.rounds = new ArrayList<>();
        rounds.addFirst(new ArrayList<>()); // Allocate the first round
        rounds.addLast(new ArrayList<>()); // Allocate the last round
        for (var extension : compatibleExtensions) {
            switch (extension) {
                case TlsConcreteExtension concreteExtension -> {
                    // Concrete extensions don't have any dependencies, so we can always process them at the beginning
                    var firstRound = rounds.getFirst();
                    firstRound.add(concreteExtension);
                }
                case TlsModelExtension<?, ?> modelExtension -> {
                    switch (modelExtension.dependencies()) {
                        // If no dependencies are needed, we can process this extension at the beginning
                        case Dependencies.None _ -> {
                            var firstRound = rounds.getFirst();
                            firstRound.add(modelExtension);
                        }

                        // If some dependencies are needed to process this extension, calculate after how many rounds it should be processed
                        case Some some -> {
                            var roundIndex = getRoundIndex(some);
                            var existingRound = rounds.get(roundIndex);
                            if (existingRound != null) {
                                existingRound.add(modelExtension);
                            } else {
                                var newRound = new ArrayList<TlsExtension>();
                                newRound.add(modelExtension);
                                rounds.set(roundIndex, newRound);
                            }
                        }

                        // If all dependencies are needed to process this extension, we can this process this extension at the end
                        case Dependencies.All _ -> {
                            var lastRound = rounds.getLast();
                            lastRound.addFirst(modelExtension);
                        }
                    }
                }
            }
        }

        // Actually process the annotations
        this.processedExtensions = new ArrayList<>();
        this.processedExtensionsLength = 0;
        this.supportedGroups = TlsSupportedGroup.supportedGroups();
        this.explicitVersionsSupport = false;
        this.greaseSupport = false;
        for (var round : rounds) {
            for (var extension : round) {
                var concrete = configureExtension(extension);
                if (concrete.isEmpty()) {
                    continue;
                }

                processedExtensions.add(concrete.get());
                processedExtensionsLength += concrete.get().extensionLength();
            }
        }

        tlsEngine.setSupportedGroups(supportedGroups);
        if(extendedMasterSecret) {
            tlsEngine.enableExtendedMasterSecret();
        }
    }

    private int getRoundIndex(Some some) {
        var roundIndex = 0;
        for (var dependency : some.includedTypes()) {
            var match = dependenciesTree.get(dependency);
            switch (match) {
                // All dependencies are linked to this match: we must process this extension as last
                case Dependencies.All _ -> {
                    return rounds.size() - 1; // No need to process further, this is already the max value we can find
                }

                // Some dependencies are linked to this match: recursively compute the depth
                case Some innerSome -> roundIndex = Math.max(roundIndex, getRoundIndex(innerSome) + 1);

                // No dependencies are linked to this match: nothing to add to our dependencies processing queue
                case Dependencies.None _ -> {}

                // No match exists in our dependency tree
                case null -> {}
            }
        }
        return roundIndex;
    }

    private Optional<? extends TlsConcreteExtension> configureExtension(TlsExtension extension) {
        return switch (extension) {
            case TlsConcreteExtension concreteExtension -> {
                switch (concreteExtension) {
                    case SupportedGroupsExtension supportedGroupsExtension -> supportedGroups = supportedGroupsExtension.groups();
                    case GreaseExtension _ -> greaseSupport = true;
                    case ClientSupportedVersionsExtension _ -> explicitVersionsSupport = true;
                    case ExtendedMasterSecretExtension _ -> extendedMasterSecret = true;
                    default -> {}
                }
                yield Optional.of(concreteExtension);
            }
            case TlsModelExtension<?, ?> modelExtension -> switch (modelExtension) {
                case SNIExtensionModel sniExtensionModel -> {
                    var hostname = tlsEngine.remoteAddress()
                            .map(InetSocketAddress::getHostName)
                            .orElse(null);
                    var config = new SNIExtensionModel.Config(hostname, SNIExtension.NameType.HOST_NAME);
                    yield sniExtensionModel.create(config);
                }

                case ClientSupportedVersionsModel clientSupportedVersionsModel -> {
                    var supportedVersions = new ArrayList<TlsVersionId>();
                    if (explicitVersionsSupport) {
                        if (greaseSupport) {
                            supportedVersions.add(TlsVersionId.grease());
                        }
                        var version = tlsEngine.config().version();
                        if (version == TlsVersion.TLS13 || version == TlsVersion.DTLS13) {
                            supportedVersions.add(version.id());
                        }
                    }
                    var config = new ClientSupportedVersionsModel.Config(supportedVersions);
                    yield clientSupportedVersionsModel.create(config);
                }

                case PaddingExtensionModel paddingExtensionModel -> {
                    var messageHeaderLength = TlsMessage.messageRecordHeaderLength();
                    var payloadNoExtensionsLength = ClientHelloMessage.getMessagePayloadLength(
                            tlsEngine.dtlsCookie().orElse(null),
                            tlsEngine.config().ciphers(),
                            tlsEngine.config().compressions()
                    );
                    var payloadHeaderLength = TlsHandshakeMessage.handshakePayloadHeaderLength(payloadNoExtensionsLength);
                    var extensionsPayloadLength = INT16_LENGTH + processedExtensionsLength;
                    var config = new PaddingExtensionModel.Config(messageHeaderLength + payloadHeaderLength + payloadNoExtensionsLength + extensionsPayloadLength);
                    yield paddingExtensionModel.create(config);
                }

                case KeyShareExtensionModel keyShareExtensionModel -> {
                    var keyPair = tlsEngine.createKeyPair();
                    var config = new KeyShareExtensionModel.Config(keyPair.rawPublicKey(), keyPair.group());
                    yield keyShareExtensionModel.create(config);
                }
            };
        };
    }

    public List<TlsConcreteExtension> extensions() {
        return Collections.unmodifiableList(processedExtensions);
    }

    public int extensionsLength() {
        return processedExtensionsLength;
    }
}
