package it.auties.leap.tls.extension;

import it.auties.leap.tls.config.TlsMode;
import it.auties.leap.tls.config.TlsVersion;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.Optional;

final class GreaseExtensionModel implements TlsExtension.Model {
    static final GreaseExtensionModel GREASE_0A = new GreaseExtensionModel(new GreaseExtension(0x0A0A));
    static final GreaseExtensionModel GREASE_1A = new GreaseExtensionModel(new GreaseExtension(0x1A1A));
    static final GreaseExtensionModel GREASE_2A = new GreaseExtensionModel(new GreaseExtension(0x2A2A));
    static final GreaseExtensionModel GREASE_3A = new GreaseExtensionModel(new GreaseExtension(0x3A3A));
    static final GreaseExtensionModel GREASE_4A = new GreaseExtensionModel(new GreaseExtension(0x4A4A));
    static final GreaseExtensionModel GREASE_5A = new GreaseExtensionModel(new GreaseExtension(0x5A5A));
    static final GreaseExtensionModel GREASE_6A = new GreaseExtensionModel(new GreaseExtension(0x6A6A));
    static final GreaseExtensionModel GREASE_7A = new GreaseExtensionModel(new GreaseExtension(0x7A7A));
    static final GreaseExtensionModel GREASE_8A = new GreaseExtensionModel(new GreaseExtension(0x8A8A));
    static final GreaseExtensionModel GREASE_9A = new GreaseExtensionModel(new GreaseExtension(0x9A9A));
    static final GreaseExtensionModel GREASE_AA = new GreaseExtensionModel(new GreaseExtension(0xAAAA));
    static final GreaseExtensionModel GREASE_BA = new GreaseExtensionModel(new GreaseExtension(0xBABA));
    static final GreaseExtensionModel GREASE_CA = new GreaseExtensionModel(new GreaseExtension(0xCACA));
    static final GreaseExtensionModel GREASE_DA = new GreaseExtensionModel(new GreaseExtension(0xDADA));
    static final GreaseExtensionModel GREASE_EA = new GreaseExtensionModel(new GreaseExtension(0xEAEA));
    static final GreaseExtensionModel GREASE_FA = new GreaseExtensionModel(new GreaseExtension(0xFAFA));

    private final GreaseExtension implementation;
    private GreaseExtensionModel(GreaseExtension implementation) {
        this.implementation = implementation;
    }

    @Override
    public Optional<? extends TlsExtension.Implementation> newInstance(TlsExtension.Model.Context context) {
        return Optional.of(implementation);
    }

    @Override
    public Optional<? extends TlsExtension.Implementation> decode(ByteBuffer buffer, int type, TlsMode mode) {
        return switch (type) {
            case 0x0A0A -> Optional.of(GREASE_0A.implementation);
            case 0x1A1A -> Optional.of(GREASE_1A.implementation);
            case 0x2A2A -> Optional.of(GREASE_2A.implementation);
            case 0x3A3A -> Optional.of(GREASE_3A.implementation);
            case 0x4A4A -> Optional.of(GREASE_4A.implementation);
            case 0x5A5A -> Optional.of(GREASE_5A.implementation);
            case 0x6A6A -> Optional.of(GREASE_6A.implementation);
            case 0x7A7A -> Optional.of(GREASE_7A.implementation);
            case 0x8A8A -> Optional.of(GREASE_8A.implementation);
            case 0x9A9A -> Optional.of(GREASE_9A.implementation);
            case 0xAAAA -> Optional.of(GREASE_AA.implementation);
            case 0xBABA -> Optional.of(GREASE_BA.implementation);
            case 0xCACA -> Optional.of(GREASE_CA.implementation);
            case 0xDADA -> Optional.of(GREASE_DA.implementation);
            case 0xEAEA -> Optional.of(GREASE_EA.implementation);
            case 0xFAFA -> Optional.of(GREASE_FA.implementation);
            default -> Optional.empty();
        };
    }

    @Override
    public Class<? extends TlsExtension.Implementation> toConcreteType(TlsMode mode) {
        return GreaseExtension.class;
    }

    @Override
    public TlsExtension.Model.Dependencies dependencies() {
        return TlsExtension.Model.Dependencies.none();
    }

    @Override
    public int extensionType() {
        return implementation.extensionType();
    }

    @Override
    public List<TlsVersion> versions() {
        return TlsExtensions.GREASE_VERSIONS;
    }

}
