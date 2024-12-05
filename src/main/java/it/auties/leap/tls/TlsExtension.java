package it.auties.leap.tls;

import it.auties.leap.tls.extension.TlsConcreteExtension;
import it.auties.leap.tls.extension.TlsModelExtension;
import it.auties.leap.tls.extension.concrete.*;
import it.auties.leap.tls.extension.model.KeyShareExtensionModel;
import it.auties.leap.tls.extension.model.PaddingExtensionModel;
import it.auties.leap.tls.extension.model.SNIExtensionModel;
import it.auties.leap.tls.extension.model.ClientSupportedVersionsModel;

import java.security.SecureRandom;
import java.util.List;

public sealed interface TlsExtension permits TlsConcreteExtension, TlsModelExtension {
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

    static TlsExtension applicationLayerProtocolNegotiation(List<String> supportedProtocols) {
        return new APLNExtension(supportedProtocols);
    }

    static TlsExtension padding(int targetLength) {
        return new PaddingExtensionModel(targetLength);
    }

    static TlsExtension ecPointFormats() {
        return ECPointFormatsExtension.ALL;
    }

    static TlsExtension ecPointFormats(List<TlsEcPointFormat> ecPointFormats) {
        return new ECPointFormatsExtension(ecPointFormats);
    }

    static TlsExtension supportedGroups() {
        return SupportedGroupsExtension.RECOMMENDED;
    }

    static TlsExtension supportedGroups(List<TlsSupportedGroup> groups) {
        return new SupportedGroupsExtension(groups);
    }

    static TlsExtension signatureAlgorithms() {
        return SignatureAlgorithmsExtension.RECOMMENDED;
    }

    static TlsExtension signatureAlgorithms(List<TlsSignatureAlgorithm> algorithms) {
        return new SignatureAlgorithmsExtension(algorithms);
    }

    static TlsExtension pskExchangeModes(List<TlsPskKeyExchangeMode> modes) {
        return new PskExchangeModesExtension(modes);
    }

    static TlsExtension keyShare() {
        return KeyShareExtensionModel.INSTANCE;
    }

    static TlsExtension grease0A() {
        return GreaseExtension.INSTANCES[0];
    }

    static TlsExtension grease1A() {
        return GreaseExtension.INSTANCES[1];
    }

    static TlsExtension grease2A() {
        return GreaseExtension.INSTANCES[2];
    }

    static TlsExtension grease3A() {
        return GreaseExtension.INSTANCES[3];
    }

    static TlsExtension grease4A() {
        return GreaseExtension.INSTANCES[4];
    }

    static TlsExtension grease5A() {
        return GreaseExtension.INSTANCES[5];
    }

    static TlsExtension grease6A() {
        return GreaseExtension.INSTANCES[6];
    }

    static TlsExtension grease7A() {
        return GreaseExtension.INSTANCES[7];
    }

    static TlsExtension grease8A() {
        return GreaseExtension.INSTANCES[8];
    }

    static TlsExtension grease9A() {
        return GreaseExtension.INSTANCES[9];
    }

    static TlsExtension greaseAA() {
        return GreaseExtension.INSTANCES[10];
    }

    static TlsExtension greaseBA() {
        return GreaseExtension.INSTANCES[11];
    }

    static TlsExtension greaseCA() {
        return GreaseExtension.INSTANCES[12];
    }

    static TlsExtension greaseDA() {
        return GreaseExtension.INSTANCES[13];
    }

    static TlsExtension greaseEA() {
        return GreaseExtension.INSTANCES[14];
    }

    static TlsExtension greaseFA() {
        return GreaseExtension.INSTANCES[15];
    }

    static TlsExtension grease() {
        var random = new SecureRandom();
        return GreaseExtension.INSTANCES[random.nextInt(0, GreaseExtension.INSTANCES.length)];
    }

    static TlsExtension grease(int index) {
        if(index < 0 || index >= GreaseExtension.INSTANCES.length) {
            throw new IndexOutOfBoundsException("Index %s is not within bounds [0, 16)".formatted(index));
        }

        return GreaseExtension.INSTANCES[index];
    }

    List<TlsVersion> versions();
}
