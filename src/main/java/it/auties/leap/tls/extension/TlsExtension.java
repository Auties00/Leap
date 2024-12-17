package it.auties.leap.tls.extension;

import it.auties.leap.tls.config.TlsEcPointFormat;
import it.auties.leap.tls.config.TlsIdentifiableUnion;
import it.auties.leap.tls.config.TlsVersion;
import it.auties.leap.tls.config.TlsVersionId;
import it.auties.leap.tls.extension.concrete.*;
import it.auties.leap.tls.extension.model.ClientSupportedVersionsModel;
import it.auties.leap.tls.extension.model.KeyShareExtensionModel;
import it.auties.leap.tls.extension.model.PaddingExtensionModel;
import it.auties.leap.tls.extension.model.SNIExtensionModel;
import it.auties.leap.tls.key.TlsPskKeyExchangeMode;
import it.auties.leap.tls.key.TlsSignatureAndHashAlgorithm;
import it.auties.leap.tls.key.TlsSupportedGroup;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static it.auties.leap.tls.BufferHelper.INT16_LENGTH;
import static it.auties.leap.tls.BufferHelper.scopedRead;

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
                .map(TlsIdentifiableUnion::of)
                .toList();
        return new ECPointFormatsExtension(wrappedFormats);
    }

    static TlsExtension supportedGroups() {
        return SupportedGroupsExtension.RECOMMENDED;
    }

    static TlsExtension supportedGroups(List<TlsSupportedGroup> groups) {
        var wrappedGroups = groups.stream()
                .map(TlsIdentifiableUnion::of)
                .toList();
        return new SupportedGroupsExtension(wrappedGroups);
    }

    static TlsExtension signatureAlgorithms() {
        return SignatureAlgorithmsExtension.RECOMMENDED;
    }

    static TlsExtension signatureAlgorithms(List<TlsSignatureAndHashAlgorithm> algorithms) {
        var wrappedAlgorithms = algorithms.stream()
                .map(TlsIdentifiableUnion::of)
                .toList();
        return new SignatureAlgorithmsExtension(wrappedAlgorithms);
    }

    static TlsExtension pskExchangeModes(List<TlsPskKeyExchangeMode> modes) {
        var wrappedModes = modes.stream()
                .map(TlsIdentifiableUnion::of)
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

    non-sealed abstract class Model<S extends Model<S, C, R>, C extends Model.Config<S>, R extends Concrete> implements TlsExtension {
        public abstract Optional<R> create(C config);
        public abstract List<TlsVersion> versions();
        public abstract Class<R> resultType();
        public abstract Dependencies dependencies();

        public interface Config<S> {

        }

        public sealed interface Dependencies {
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
    }

    // TODO: Drop ofServer and ofClient and use stored extensions for deserialization
    non-sealed abstract class Concrete implements TlsExtension {
        public static Optional<? extends Concrete> ofServer(TlsVersion version, int type, ByteBuffer buffer, int extensionLength) {
            try(var _ = scopedRead(buffer, extensionLength)) {
                if(GreaseExtension.isGrease(type)) {
                    return GreaseExtension.of(version, type);
                }

                return switch (type) {
                    case ALPNExtension.EXTENSION_TYPE -> ALPNExtension.of(version, buffer, extensionLength);
                    case ECPointFormatsExtension.EXTENSION_TYPE -> ECPointFormatsExtension.of(version, buffer, extensionLength);
                    case EncryptThenMacExtension.EXTENSION_TYPE -> EncryptThenMacExtension.of(version, buffer, extensionLength);
                    case ExtendedMasterSecretExtension.EXTENSION_TYPE -> ExtendedMasterSecretExtension.of(version, buffer, extensionLength);
                    case KeyShareExtension.EXTENSION_TYPE -> KeyShareExtension.of(version, buffer, extensionLength);
                    case ServerNextProtocolNegotiationExtension.EXTENSION_TYPE -> ServerNextProtocolNegotiationExtension.of(version, buffer, extensionLength);
                    case PaddingExtension.EXTENSION_TYPE -> PaddingExtension.of(version, buffer, extensionLength);
                    case PostHandshakeAuthExtension.EXTENSION_TYPE -> PostHandshakeAuthExtension.of(version, buffer, extensionLength);
                    case PskExchangeModesExtension.EXTENSION_TYPE -> PskExchangeModesExtension.of(version, buffer, extensionLength);
                    case SignatureAlgorithmsExtension.EXTENSION_TYPE -> SignatureAlgorithmsExtension.of(version, buffer, extensionLength);
                    case SNIExtension.EXTENSION_TYPE -> SNIExtension.of(version, buffer, extensionLength);
                    case SupportedGroupsExtension.EXTENSION_TYPE -> SupportedGroupsExtension.of(version, buffer, extensionLength);
                    case ServerSupportedVersionsExtension.EXTENSION_TYPE -> ServerSupportedVersionsExtension.of(version, buffer, extensionLength);
                    default -> Optional.empty();
                };
            }
        }

        public static Optional<? extends Concrete> ofClient(TlsVersion version, int type, ByteBuffer buffer, int extensionLength) {
            try(var _ = scopedRead(buffer, extensionLength)) {
                if(GreaseExtension.isGrease(type)) {
                    return GreaseExtension.of(version, type);
                }

                return switch (type) {
                    case ALPNExtension.EXTENSION_TYPE -> ALPNExtension.of(version, buffer, extensionLength);
                    case ECPointFormatsExtension.EXTENSION_TYPE -> ECPointFormatsExtension.of(version, buffer, extensionLength);
                    case EncryptThenMacExtension.EXTENSION_TYPE -> EncryptThenMacExtension.of(version, buffer, extensionLength);
                    case ExtendedMasterSecretExtension.EXTENSION_TYPE -> ExtendedMasterSecretExtension.of(version, buffer, extensionLength);
                    case KeyShareExtension.EXTENSION_TYPE -> KeyShareExtension.of(version, buffer, extensionLength);
                    case ClientNextProtocolNegotiationExtension.EXTENSION_TYPE -> ClientNextProtocolNegotiationExtension.of(version, buffer, extensionLength);
                    case PaddingExtension.EXTENSION_TYPE -> PaddingExtension.of(version, buffer, extensionLength);
                    case PostHandshakeAuthExtension.EXTENSION_TYPE -> PostHandshakeAuthExtension.of(version, buffer, extensionLength);
                    case PskExchangeModesExtension.EXTENSION_TYPE -> PskExchangeModesExtension.of(version, buffer, extensionLength);
                    case SignatureAlgorithmsExtension.EXTENSION_TYPE -> SignatureAlgorithmsExtension.of(version, buffer, extensionLength);
                    case SNIExtension.EXTENSION_TYPE -> SNIExtension.of(version, buffer, extensionLength);
                    case SupportedGroupsExtension.EXTENSION_TYPE -> SupportedGroupsExtension.of(version, buffer, extensionLength);
                    case ClientSupportedVersionsExtension.EXTENSION_TYPE -> ClientSupportedVersionsExtension.of(version, buffer, extensionLength);
                    default -> Optional.empty();
                };
            }
        }

        public void serializeExtension(ByteBuffer buffer) {
            var extensionType = extensionType();
            buffer.put((byte) (extensionType >> 8));
            buffer.put((byte) (extensionType));
            var extensionLength = extensionPayloadLength();
            buffer.put((byte) (extensionLength >> 8));
            buffer.put((byte) (extensionLength));
            serializeExtensionPayload(buffer);
        }

        public int extensionLength() {
            return INT16_LENGTH + INT16_LENGTH + extensionPayloadLength();
        }

        protected abstract void serializeExtensionPayload(ByteBuffer buffer);

        public abstract int extensionPayloadLength();

        public abstract int extensionType();

        public abstract List<TlsVersion> versions();
    }
}
