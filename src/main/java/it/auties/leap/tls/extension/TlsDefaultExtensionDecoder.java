package it.auties.leap.tls.extension;

import it.auties.leap.tls.config.TlsVersion;
import it.auties.leap.tls.extension.concrete.ALPNExtension;
import it.auties.leap.tls.extension.concrete.*;

import java.nio.ByteBuffer;
import java.util.Optional;

import static it.auties.leap.tls.BufferHelper.scopedRead;

final class TlsDefaultExtensionDecoder implements TlsExtension.Concrete.Decoder {
    static final TlsDefaultExtensionDecoder INSTANCE = new TlsDefaultExtensionDecoder();

    @Override
    public Optional<? extends TlsExtension.Concrete> decodeClient(TlsVersion version, int type, ByteBuffer buffer, int extensionLength) {
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

    @Override
    public Optional<? extends TlsExtension.Concrete> decodeServer(TlsVersion version, int type, ByteBuffer buffer, int extensionLength) {
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
}
