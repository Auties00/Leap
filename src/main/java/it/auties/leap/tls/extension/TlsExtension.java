package it.auties.leap.tls.extension;

import it.auties.leap.tls.config.TlsConfig;
import it.auties.leap.tls.config.TlsEcPointFormat;
import it.auties.leap.tls.config.TlsVersion;
import it.auties.leap.tls.config.TlsVersionId;
import it.auties.leap.tls.extension.concrete.ALPNExtension;
import it.auties.leap.tls.extension.concrete.*;
import it.auties.leap.tls.extension.model.ClientSupportedVersionsModel;
import it.auties.leap.tls.extension.model.KeyShareExtensionModel;
import it.auties.leap.tls.extension.model.PaddingExtensionModel;
import it.auties.leap.tls.extension.model.SNIExtensionModel;
import it.auties.leap.tls.key.TlsPskKeyExchangeMode;
import it.auties.leap.tls.key.TlsSignatureAndHashAlgorithm;
import it.auties.leap.tls.key.TlsSupportedGroup;

import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.util.*;
import java.util.function.Predicate;

import static it.auties.leap.tls.BufferHelper.INT16_LENGTH;

public sealed interface TlsExtension permits TlsExtension.Concrete, TlsExtension.Model {
    static TlsExtension extendedMasterSecret() {
        return ExtendedMasterSecretExtension.INSTANCE;
    }

    static TlsExtension encryptThenMac() {
        return EncryptThenMacExtension.INSTANCE;
    }

    static TlsExtension postHandshakeAuth() {
        return PostHandshakeAuthExtension.INSTANCE;
    }

    static TlsExtension nextProtocolNegotiation() {
        return ClientNextProtocolNegotiationExtension.INSTANCE;
    }

    static TlsExtension serverNameIndication() {
        return SNIExtensionModel.INSTANCE;
    }

    static TlsExtension supportedVersions() {
        return ClientSupportedVersionsModel.INSTANCE;
    }

    static TlsExtension supportedVersions(List<TlsVersionId> tlsVersions) {
        return new ClientSupportedVersionsExtension(tlsVersions);
    }

    static TlsExtension alpn(List<String> supportedProtocols) {
        var wrappedProtocols = supportedProtocols.stream()
                .map(String::getBytes)
                .toList();
        return new ALPNExtension(wrappedProtocols);
    }

    static TlsExtension padding(int targetLength) {
        return new PaddingExtensionModel(targetLength);
    }

    static TlsExtension ecPointFormats() {
        return ECPointFormatsExtension.ALL;
    }

    static TlsExtension ecPointFormats(List<TlsEcPointFormat> formats) {
        var wrappedFormats = formats.stream()
                .map(TlsEcPointFormat::id)
                .toList();
        return new ECPointFormatsExtension(wrappedFormats);
    }

    static TlsExtension supportedGroups() {
        return SupportedGroupsExtension.RECOMMENDED;
    }

    static TlsExtension supportedGroups(List<TlsSupportedGroup> groups) {
        var wrappedGroups = groups.stream()
                .map(TlsSupportedGroup::id)
                .toList();
        return new SupportedGroupsExtension(wrappedGroups);
    }

    static TlsExtension signatureAlgorithms() {
        return SignatureAlgorithmsExtension.RECOMMENDED;
    }

    static TlsExtension signatureAlgorithms(List<TlsSignatureAndHashAlgorithm> algorithms) {
        var wrappedAlgorithms = algorithms.stream()
                .map(TlsSignatureAndHashAlgorithm::id)
                .toList();
        return new SignatureAlgorithmsExtension(wrappedAlgorithms);
    }

    static TlsExtension pskExchangeModes(List<TlsPskKeyExchangeMode> modes) {
        var wrappedModes = modes.stream()
                .map(TlsPskKeyExchangeMode::id)
                .toList();
        return new PskExchangeModesExtension(wrappedModes);
    }

    static TlsExtension keyShare() {
        return KeyShareExtensionModel.INSTANCE;
    }

    static TlsExtension grease0A() {
        return GreaseExtension.GREASE_0A;
    }

    static TlsExtension grease1A() {
        return GreaseExtension.GREASE_1A;
    }

    static TlsExtension grease2A() {
        return GreaseExtension.GREASE_2A;
    }

    static TlsExtension grease3A() {
        return GreaseExtension.GREASE_3A;
    }

    static TlsExtension grease4A() {
        return GreaseExtension.GREASE_4A;
    }

    static TlsExtension grease5A() {
        return GreaseExtension.GREASE_5A;
    }

    static TlsExtension grease6A() {
        return GreaseExtension.GREASE_6A;
    }

    static TlsExtension grease7A() {
        return GreaseExtension.GREASE_7A;
    }

    static TlsExtension grease8A() {
        return GreaseExtension.GREASE_8A;
    }

    static TlsExtension grease9A() {
        return GreaseExtension.GREASE_9A;
    }

    static TlsExtension greaseAA() {
        return GreaseExtension.GREASE_AA;
    }

    static TlsExtension greaseBA() {
        return GreaseExtension.GREASE_BA;
    }

    static TlsExtension greaseCA() {
        return GreaseExtension.GREASE_CA;
    }

    static TlsExtension greaseDA() {
        return GreaseExtension.GREASE_DA;
    }

    static TlsExtension greaseEA() {
        return GreaseExtension.GREASE_EA;
    }

    static TlsExtension greaseFA() {
        return GreaseExtension.GREASE_FA;
    }

    static List<? extends TlsExtension> grease() {
        return GreaseExtension.INSTANCES;
    }

    List<TlsVersion> versions();

    non-sealed interface Model<P extends Concrete> extends TlsExtension {
        Optional<P> create(Context context);
        List<TlsVersion> versions();
        Class<P> resultType();
        Dependencies dependencies();

        sealed interface Dependencies {
            static None none() {
                return None.INSTANCE;
            }

            @SafeVarargs
            static Some some(Class<? extends Concrete>... includedTypes) {
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
                private final Set<Class<? extends Concrete>> includedTypes;
                private Some(Set<Class<? extends Concrete>> includedTypes) {
                    this.includedTypes = includedTypes;
                }

                public Set<Class<? extends Concrete>> includedTypes() {
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
            public static Context of(InetSocketAddress address, TlsConfig config) {
                return new Context(address, config);
            }

            private final InetSocketAddress address;
            private final TlsConfig config;
            private final List<TlsExtension.Concrete> processedExtensions;
            private final Set<Integer> processedExtensionTypes;
            private int processedExtensionsLength;
            private Context(InetSocketAddress address, TlsConfig config) {
                this.address = address;
                this.config = config;
                this.processedExtensionTypes = new HashSet<>();
                this.processedExtensions = new ArrayList<>();
            }

            public InetSocketAddress address() {
                return address;
            }

            public TlsConfig config() {
                return config;
            }

            public List<Concrete> processedExtensions() {
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

            public void putExtension(Concrete concrete) {
                processedExtensions.add(concrete);
                processedExtensionTypes.add(concrete.extensionType());
                processedExtensionsLength += concrete.extensionLength();
            }
        }
    }

    non-sealed interface Concrete extends TlsExtension {
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

        int extensionType();

        List<TlsVersion> versions();

        interface Decoder {
            static Decoder standard() {
                return TlsDefaultExtensionDecoder.INSTANCE;
            }

            Optional<? extends Concrete> decodeServer(TlsVersion version, int type, ByteBuffer buffer, int extensionLength);
            Optional<? extends Concrete> decodeClient(TlsVersion version, int type, ByteBuffer buffer, int extensionLength);
        }
    }
}
