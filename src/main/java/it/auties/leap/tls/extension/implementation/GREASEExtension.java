package it.auties.leap.tls.extension.implementation;

import it.auties.leap.tls.context.TlsMode;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.extension.TlsExtensionDeserializer;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

public final class GREASEExtension implements TlsExtension.Concrete {
    private static final GREASEExtension GREASE_0A = new GREASEExtension(0x0A0A);
    private static final GREASEExtension GREASE_1A = new GREASEExtension(0x1A1A);
    private static final GREASEExtension GREASE_2A = new GREASEExtension(0x2A2A);
    private static final GREASEExtension GREASE_3A = new GREASEExtension(0x3A3A);
    private static final GREASEExtension GREASE_4A = new GREASEExtension(0x4A4A);
    private static final GREASEExtension GREASE_5A = new GREASEExtension(0x5A5A);
    private static final GREASEExtension GREASE_6A = new GREASEExtension(0x6A6A);
    private static final GREASEExtension GREASE_7A = new GREASEExtension(0x7A7A);
    private static final GREASEExtension GREASE_8A = new GREASEExtension(0x8A8A);
    private static final GREASEExtension GREASE_9A = new GREASEExtension(0x9A9A);
    private static final GREASEExtension GREASE_AA = new GREASEExtension(0xAAAA);
    private static final GREASEExtension GREASE_BA = new GREASEExtension(0xBABA);
    private static final GREASEExtension GREASE_CA = new GREASEExtension(0xCACA);
    private static final GREASEExtension GREASE_DA = new GREASEExtension(0xDADA);
    private static final GREASEExtension GREASE_EA = new GREASEExtension(0xEAEA);
    private static final GREASEExtension GREASE_FA = new GREASEExtension(0xFAFA);
    private static final List<GREASEExtension> VALUES = List.of(GREASE_0A, GREASE_1A, GREASE_2A, GREASE_3A, GREASE_4A, GREASE_5A, GREASE_6A, GREASE_7A, GREASE_8A, GREASE_9A, GREASE_AA, GREASE_BA, GREASE_CA, GREASE_DA, GREASE_EA, GREASE_FA);

    private static final TlsExtensionDeserializer DECODER = new TlsExtensionDeserializer() {
        @Override
        public Optional<? extends Concrete> deserialize(ByteBuffer buffer, TlsSource source, TlsMode mode, int type) {
            return switch (type) {
                case 0x0A0A -> Optional.of(GREASE_0A);
                case 0x1A1A -> Optional.of(GREASE_1A);
                case 0x2A2A -> Optional.of(GREASE_2A);
                case 0x3A3A -> Optional.of(GREASE_3A);
                case 0x4A4A -> Optional.of(GREASE_4A);
                case 0x5A5A -> Optional.of(GREASE_5A);
                case 0x6A6A -> Optional.of(GREASE_6A);
                case 0x7A7A -> Optional.of(GREASE_7A);
                case 0x8A8A -> Optional.of(GREASE_8A);
                case 0x9A9A -> Optional.of(GREASE_9A);
                case 0xAAAA -> Optional.of(GREASE_AA);
                case 0xBABA -> Optional.of(GREASE_BA);
                case 0xCACA -> Optional.of(GREASE_CA);
                case 0xDADA -> Optional.of(GREASE_DA);
                case 0xEAEA -> Optional.of(GREASE_EA);
                case 0xFAFA -> Optional.of(GREASE_FA);
                default -> Optional.empty();
            };
        }

    };

    private final int extensionType;
    private GREASEExtension(int extensionType) {
        this.extensionType = extensionType;
    }

    public static GREASEExtension grease0A() {
        return GREASE_0A;
    }

    public static GREASEExtension grease1A() {
        return GREASE_1A;
    }

    public static GREASEExtension grease2A() {
        return GREASE_2A;
    }

    public static GREASEExtension grease3A() {
        return GREASE_3A;
    }

    public static GREASEExtension grease4A() {
        return GREASE_4A;
    }

    public static GREASEExtension grease5A() {
        return GREASE_5A;
    }

    public static GREASEExtension grease6A() {
        return GREASE_6A;
    }

    public static GREASEExtension grease7A() {
        return GREASE_7A;
    }

    public static GREASEExtension grease8A() {
        return GREASE_8A;
    }

    public static GREASEExtension grease9A() {
        return GREASE_9A;
    }

    public static GREASEExtension greaseAA() {
        return GREASE_AA;
    }

    public static GREASEExtension greaseBA() {
        return GREASE_BA;
    }

    public static GREASEExtension greaseCA() {
        return GREASE_CA;
    }

    public static GREASEExtension greaseDA() {
        return GREASE_DA;
    }

    public static GREASEExtension greaseEA() {
        return GREASE_EA;
    }

    public static GREASEExtension greaseFA() {
        return GREASE_FA;
    }

    public static List<GREASEExtension> greaseValues() {
        return VALUES;
    }

    @Override
    public void serializeExtensionPayload(ByteBuffer buffer) {

    }

    @Override
    public int extensionPayloadLength() {
        return 0;
    }

    @Override
    public List<TlsVersion> versions() {
        return GREASE_VERSIONS;
    }

    @Override
    public int extensionType() {
        return extensionType;
    }

    @Override
    public TlsExtensionDeserializer decoder() {
        return DECODER;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == this) return true;
        if (obj == null || obj.getClass() != this.getClass()) return false;
        var that = (GREASEExtension) obj;
        return this.extensionType == that.extensionType;
    }

    @Override
    public int hashCode() {
        return Objects.hash(extensionType);
    }

    @Override
    public String toString() {
        return "GREASEExtension[" +
                "extensionType=" + extensionType + ']';
    }
}
