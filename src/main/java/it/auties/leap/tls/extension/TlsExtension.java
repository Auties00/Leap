package it.auties.leap.tls.extension;

import it.auties.leap.tls.config.*;
import it.auties.leap.tls.extension.model.*;
import it.auties.leap.tls.extension.model.ClientSupportedVersionsModel;
import it.auties.leap.tls.key.TlsPskKeyExchangeMode;
import it.auties.leap.tls.signature.TlsSignatureAndHashAlgorithm;
import it.auties.leap.tls.key.TlsSupportedGroup;

import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.util.*;
import java.util.function.Predicate;

import static it.auties.leap.tls.util.BufferHelper.INT16_LENGTH;

public sealed interface TlsExtension {
    static TlsExtension extendedMasterSecret() {
        return ExtendedMasterSecretExtensionModel.INSTANCE;
    }

    static TlsExtension encryptThenMac() {
        return EncryptThenMacExtensionModel.INSTANCE;
    }

    static TlsExtension postHandshakeAuth() {
        return PostHandshakeAuthExtension.INSTANCE;
    }

    static TlsExtension nextProtocolNegotiation() {
        return NextProtocolNegotiationClientExtension.INSTANCE;
    }

    static TlsExtension serverNameIndication() {
        return ServerNameIndiciationExtensionModel.INSTANCE;
    }

    static TlsExtension supportedVersions() {
        return ClientSupportedVersionsModel.INSTANCE;
    }

    static TlsExtension supportedVersions(List<TlsVersionId> tlsVersions) {
        return new SupportedVersionsExtensionModel.Implementation(tlsVersions);
    }

    static TlsExtension alpn(List<String> supportedProtocols) {
        var wrappedProtocols = supportedProtocols.stream()
                .map(String::getBytes)
                .toList();
        return new ApplicationLayerProtocolNegotiationExtension.Shared(wrappedProtocols);
    }

    static TlsExtension padding(int targetLength) {
        return new PaddingExtensionModel(targetLength);
    }

    static TlsExtension ecPointFormats() {
        return ECPointFormatExtensionModel.Shared.ALL;
    }

    static TlsExtension ecPointFormats(List<TlsEcPointFormat> formats) {
        var wrappedFormats = formats.stream()
                .map(TlsEcPointFormat::id)
                .toList();
        return new ECPointFormatExtensionModel.Shared(wrappedFormats);
    }

    static TlsExtension supportedGroups() {
        return SupportedGroupsExtensionModel.RECOMMENDED;
    }

    static TlsExtension supportedGroups(List<TlsSupportedGroup> groups) {
        var wrappedGroups = groups.stream()
                .map(TlsSupportedGroup::id)
                .toList();
        return new SupportedGroupsExtensionModel(wrappedGroups);
    }

    static TlsExtension signatureAlgorithms() {
        return SignatureAlgorithmsExtensionModel.RECOMMENDED;
    }

    static TlsExtension signatureAlgorithms(List<TlsSignatureAndHashAlgorithm> algorithms) {
        var wrappedAlgorithms = algorithms.stream()
                .map(TlsSignatureAndHashAlgorithm::id)
                .toList();
        return new SignatureAlgorithmsExtensionModel(wrappedAlgorithms);
    }

    static TlsExtension pskExchangeModes(List<TlsPskKeyExchangeMode> modes) {
        var wrappedModes = modes.stream()
                .map(TlsPskKeyExchangeMode::id)
                .toList();
        return new PskExchangeModesExtensionModel(wrappedModes);
    }

    static TlsExtension keyShare() {
        return KeyShareExtensionModel.INSTANCE;
    }

    static TlsExtension grease0A() {
        return GreaseExtensionModel.GREASE_0A;
    }

    static TlsExtension grease1A() {
        return GreaseExtensionModel.GREASE_1A;
    }

    static TlsExtension grease2A() {
        return GreaseExtensionModel.GREASE_2A;
    }

    static TlsExtension grease3A() {
        return GreaseExtensionModel.GREASE_3A;
    }

    static TlsExtension grease4A() {
        return GreaseExtensionModel.GREASE_4A;
    }

    static TlsExtension grease5A() {
        return GreaseExtensionModel.GREASE_5A;
    }

    static TlsExtension grease6A() {
        return GreaseExtensionModel.GREASE_6A;
    }

    static TlsExtension grease7A() {
        return GreaseExtensionModel.GREASE_7A;
    }

    static TlsExtension grease8A() {
        return GreaseExtensionModel.GREASE_8A;
    }

    static TlsExtension grease9A() {
        return GreaseExtensionModel.GREASE_9A;
    }

    static TlsExtension greaseAA() {
        return GreaseExtensionModel.GREASE_AA;
    }

    static TlsExtension greaseBA() {
        return GreaseExtensionModel.GREASE_BA;
    }

    static TlsExtension greaseCA() {
        return GreaseExtensionModel.GREASE_CA;
    }

    static TlsExtension greaseDA() {
        return GreaseExtensionModel.GREASE_DA;
    }

    static TlsExtension greaseEA() {
        return GreaseExtensionModel.GREASE_EA;
    }

    static TlsExtension greaseFA() {
        return GreaseExtensionModel.GREASE_FA;
    }

    static List<? extends TlsExtension> grease() {
        return GreaseExtensionModel.INSTANCES;
    }

    int extensionType();
    List<TlsVersion> versions();

    non-sealed interface Model extends TlsExtension {
        Optional<? extends Implementation> newInstance(Context context);
        Optional<? extends Implementation> decode(ByteBuffer buffer, int type, TlsMode mode);
        Class<? extends Implementation> toConcreteType(TlsMode mode);
        Dependencies dependencies();

        sealed interface Dependencies {
            static None none() {
                return None.INSTANCE;
            }

            @SafeVarargs
            static Some some(Class<? extends Implementation>... includedTypes) {
                return new Some(Set.of(includedTypes));
            }

            static All all() {
                return All.INSTANCE;
            }

            final class None implements Dependencies {
                private static final None INSTANCE = new None();
                private None() {

                }
            }

            final class Some implements Dependencies {
                private final Set<Class<? extends Implementation>> includedTypes;
                private Some(Set<Class<? extends Implementation>> includedTypes) {
                    this.includedTypes = includedTypes;
                }

                public Set<Class<? extends Implementation>> includedTypes() {
                    return includedTypes;
                }
            }

            final class All implements Dependencies {
                private static final All INSTANCE = new All();
                private All() {

                }
            }
        }

        final class Context {
            public static Context of(InetSocketAddress address, TlsConfig config, TlsMode mode) {
                return new Context(address, config, mode);
            }

            private final InetSocketAddress address;
            private final TlsConfig config;
            private final TlsMode mode;
            private final List<Implementation> processedExtensions;
            private final Set<Integer> processedExtensionTypes;
            private int processedExtensionsLength;
            private Context(InetSocketAddress address, TlsConfig config, TlsMode mode) {
                this.address = address;
                this.config = config;
                this.processedExtensionTypes = new HashSet<>();
                this.processedExtensions = new ArrayList<>();
                this.mode = mode;
            }

            public InetSocketAddress address() {
                return address;
            }

            public TlsConfig config() {
                return config;
            }

            public TlsMode mode() {
                return mode;
            }

            public List<Implementation> processedExtensions() {
                return Collections.unmodifiableList(processedExtensions);
            }

            public int processedExtensionsLength() {
                return processedExtensionsLength;
            }

            public boolean hasExtension(int extensionType) {
                return processedExtensionTypes.contains(extensionType);
            }

            public boolean hasExtension(Predicate<Integer> extension) {
                return processedExtensionTypes.stream().anyMatch(extension);
            }

            public void putExtension(Implementation implementation) {
                processedExtensions.add(implementation);
                processedExtensionTypes.add(implementation.extensionType());
                processedExtensionsLength += implementation.extensionLength();
            }
        }
    }

    non-sealed interface Implementation extends TlsExtension {
        default void serializeExtension(ByteBuffer buffer) {
            var extensionType = extensionType();
            buffer.put((byte) (extensionType >> 8));
            buffer.put((byte) (extensionType));
            var extensionLength = extensionPayloadLength();
            buffer.put((byte) (extensionLength >> 8));
            buffer.put((byte) (extensionLength));
            serializeExtensionPayload(buffer);
        }

        default int extensionLength() {
            return INT16_LENGTH + INT16_LENGTH + extensionPayloadLength();
        }

        void serializeExtensionPayload(ByteBuffer buffer);

        int extensionPayloadLength();
    }
}
