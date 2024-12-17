package it.auties.leap.tls.extension.concrete;

import it.auties.leap.tls.config.TlsVersion;
import it.auties.leap.tls.extension.TlsExtension;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;

public final class GreaseExtension extends TlsExtension.Concrete {
    public static final GreaseExtension GREASE_0A = new GreaseExtension(0x0A0A);
    public static final GreaseExtension GREASE_1A = new GreaseExtension(0x1A1A);
    public static final GreaseExtension GREASE_2A = new GreaseExtension(0x2A2A);
    public static final GreaseExtension GREASE_3A = new GreaseExtension(0x3A3A);
    public static final GreaseExtension GREASE_4A = new GreaseExtension(0x4A4A);
    public static final GreaseExtension GREASE_5A = new GreaseExtension(0x5A5A);
    public static final GreaseExtension GREASE_6A = new GreaseExtension(0x6A6A);
    public static final GreaseExtension GREASE_7A = new GreaseExtension(0x7A7A);
    public static final GreaseExtension GREASE_8A = new GreaseExtension(0x8A8A);
    public static final GreaseExtension GREASE_9A = new GreaseExtension(0x9A9A);
    public static final GreaseExtension GREASE_AA = new GreaseExtension(0xAAAA);
    public static final GreaseExtension GREASE_BA = new GreaseExtension(0xBABA);
    public static final GreaseExtension GREASE_CA = new GreaseExtension(0xCACA);
    public static final GreaseExtension GREASE_DA = new GreaseExtension(0xDADA);
    public static final GreaseExtension GREASE_EA = new GreaseExtension(0xEAEA);
    public static final GreaseExtension GREASE_FA = new GreaseExtension(0xFAFA);
    public static final List<GreaseExtension> INSTANCES = List.of(GREASE_0A, GREASE_1A, GREASE_2A, GREASE_3A, GREASE_4A, GREASE_5A, GREASE_6A, GREASE_7A, GREASE_8A, GREASE_9A, GREASE_AA, GREASE_BA, GREASE_CA, GREASE_DA, GREASE_EA, GREASE_FA);
    private static final Map<Integer, GreaseExtension> VALUES = INSTANCES.stream()
            .collect(Collectors.toUnmodifiableMap(GreaseExtension::extensionType, Function.identity()));

    public static Optional<GreaseExtension> of(TlsVersion version, int type) {
        if(!GreaseExtension.isGrease(type)) {
            return Optional.empty();
        }

        var grease = VALUES.get(type);
        if(grease == null) {
            return Optional.empty();
        }

        return Optional.of(grease);
    }

    private final int extensionType;
    private GreaseExtension(int extensionType) {
        this.extensionType = extensionType;
    }

    public static boolean isGrease(int extensionType) {
        return (extensionType & 0x0f0f) == 0x0a0a;
    }

    @Override
    protected void serializeExtensionPayload(ByteBuffer buffer) {

    }

    @Override
    public int extensionPayloadLength() {
        return 0;
    }

    @Override
    public int extensionType() {
        return extensionType;
    }

    @Override
    public List<TlsVersion> versions() {
        return List.of(TlsVersion.TLS12, TlsVersion.TLS13);
    }
}
