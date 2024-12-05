package it.auties.leap.tls.extension;

import it.auties.leap.tls.TlsExtension;
import it.auties.leap.tls.TlsVersion;
import it.auties.leap.tls.extension.concrete.*;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.Optional;

import static it.auties.leap.tls.TlsRecord.*;

public sealed abstract class TlsConcreteExtension implements TlsExtension
        permits APLNExtension, ClientNextProtocolNegotiationExtension, ClientSupportedVersionsExtension, ECPointFormatsExtension, EncryptThenMacExtension, ExtendedMasterSecretExtension, GreaseExtension, KeyShareExtension, PaddingExtension, PostHandshakeAuthExtension, PskExchangeModesExtension, SNIExtension, ServerNextProtocolNegotiationExtension, ServerSupportedVersionsExtension, SignatureAlgorithmsExtension, SupportedGroupsExtension {
    public static Optional<? extends TlsConcreteExtension> ofServer(TlsVersion version, int type, ByteBuffer buffer, int extensionLength) {
        try(var _ = scopedRead(buffer, extensionLength)) {
            if(GreaseExtension.isGrease(type)) {
                return GreaseExtension.of(version, type);
            }

            return switch (type) {
                case APLNExtension.EXTENSION_TYPE -> APLNExtension.of(version, buffer, extensionLength);
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

    public static Optional<? extends TlsConcreteExtension> ofClient(TlsVersion version, int type, ByteBuffer buffer, int extensionLength) {
        try(var _ = scopedRead(buffer, extensionLength)) {
            if(GreaseExtension.isGrease(type)) {
                return GreaseExtension.of(version, type);
            }

            return switch (type) {
                case APLNExtension.EXTENSION_TYPE -> APLNExtension.of(version, buffer, extensionLength);
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
