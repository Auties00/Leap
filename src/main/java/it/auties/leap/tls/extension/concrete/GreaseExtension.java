package it.auties.leap.tls.extension.concrete;

import it.auties.leap.tls.TlsVersion;
import it.auties.leap.tls.extension.TlsConcreteExtension;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;

public final class GreaseExtension extends TlsConcreteExtension {
    public static final GreaseExtension[] INSTANCES = new GreaseExtension[]{
            new GreaseExtension(0x0A0A),
            new GreaseExtension(0x1A1A),
            new GreaseExtension(0x2A2A),
            new GreaseExtension(0x3A3A),
            new GreaseExtension(0x4A4A),
            new GreaseExtension(0x5A5A),
            new GreaseExtension(0x6A6A),
            new GreaseExtension(0x7A7A),
            new GreaseExtension(0x8A8A),
            new GreaseExtension(0x9A9A),
            new GreaseExtension(0xAAAA),
            new GreaseExtension(0xBABA),
            new GreaseExtension(0xCACA),
            new GreaseExtension(0xDADA),
            new GreaseExtension(0xEAEA),
            new GreaseExtension(0xFAFA)
    };
    private static final Map<Integer, GreaseExtension> VALUES = Arrays.stream(INSTANCES)
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
