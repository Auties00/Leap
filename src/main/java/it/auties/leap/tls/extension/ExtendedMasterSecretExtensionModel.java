package it.auties.leap.tls.extension;

import it.auties.leap.tls.config.TlsMode;
import it.auties.leap.tls.config.TlsVersion;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.Optional;

final class ExtendedMasterSecretExtensionModel implements TlsExtension.Model {
    static final ExtendedMasterSecretExtensionModel INSTANCE = new ExtendedMasterSecretExtensionModel();
    private ExtendedMasterSecretExtensionModel() {

    }

    @Override
    public Optional<? extends TlsExtension.Implementation> newInstance(TlsExtension.Model.Context context) {
        return Optional.of(ExtendedMasterSecretExtension.INSTANCE);
    }

    @Override
    public Optional<? extends TlsExtension.Implementation> decode(ByteBuffer buffer, int type, TlsMode mode) {
        if(buffer.hasRemaining()) {
            throw new IllegalArgumentException("Unexpected extension payload");
        }

        return Optional.of(ExtendedMasterSecretExtension.INSTANCE);
    }

    @Override
    public Class<? extends TlsExtension.Implementation> toConcreteType(TlsMode mode) {
        return ExtendedMasterSecretExtension.class;
    }

    @Override
    public TlsExtension.Model.Dependencies dependencies() {
        return TlsExtension.Model.Dependencies.none();
    }

    @Override
    public int extensionType() {
        return TlsExtensions.EXTENDED_MASTER_SECRET_TYPE;
    }

    @Override
    public List<TlsVersion> versions() {
        return TlsExtensions.EXTENDED_MASTER_SECRET_VERSIONS;
    }
}
