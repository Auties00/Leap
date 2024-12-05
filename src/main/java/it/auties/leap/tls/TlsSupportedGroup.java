package it.auties.leap.tls;

import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

// https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8
public enum TlsSupportedGroup {
    // ECDH
    SECT163K1(1, false, true, Type.ECDH),
    SECT163R1(2, false, true, Type.ECDH),
    SECT163R2(3, false, true, Type.ECDH),
    SECT193R1(4, false, true, Type.ECDH),
    SECT193R2(5, false, true, Type.ECDH),
    SECT233K1(6, false, true, Type.ECDH),
    SECT233R1(7, false, true, Type.ECDH),
    SECT239K1(8, false, true, Type.ECDH),
    SECT283K1(9, false, true, Type.ECDH),
    SECT283R1(10, false, true, Type.ECDH),
    SECT409K1(11, false, true, Type.ECDH),
    SECT409R1(12, false, true, Type.ECDH),
    SECT571K1(13, false, true, Type.ECDH),
    SECT571R1(14, false, true, Type.ECDH),
    SECP160K1(15, false, true, Type.ECDH),
    SECP160R1(16, false, true, Type.ECDH),
    SECP160R2(17, false, true, Type.ECDH),
    SECP192K1(18, false, true, Type.ECDH),
    SECP192R1(19, false, true, Type.ECDH),
    SECP224K1(20, false, true, Type.ECDH),
    SECP224R1(21, false, true, Type.ECDH),
    SECP256K1(22, false, true, Type.ECDH),
    SECP256R1(23, true, true, Type.ECDH),
    SECP384R1(24, true, true, Type.ECDH),
    SECP521R1(25, false, true, Type.ECDH),
    BRAINPOOLP256R1(26, false, true, Type.ECDH),
    BRAINPOOLP384R1(27, false, true, Type.ECDH),
    BRAINPOOLP512R1(28, false, true, Type.ECDH),
    X25519(29, true, true, Type.ECDH),
    X448(30, true, true, Type.ECDH),
    BRAINPOOLP256R1TLS13(31, false, true, Type.ECDH),
    BRAINPOOLP384R1TLS13(32, false, true, Type.ECDH),
    BRAINPOOLP512R1TLS13(33, false, true, Type.ECDH),
    GC256A(34, false, true, Type.ECDH),
    GC256B(35, false, true, Type.ECDH),
    GC256C(36, false, true, Type.ECDH),
    GC256D(37, false, true, Type.ECDH),
    GC512A(38, false, true, Type.ECDH),
    GC512B(39, false, true, Type.ECDH),
    GC512C(40, false, false, Type.ECDH),
    CURVESM2(41, false, true, Type.ECDH),

    // DHE
    FFDHE2048(256, false, true, Type.DH),
    FFDHE3072(257, false, true, Type.DH),
    FFDHE4096(258, false, true, Type.DH),
    FFDHE6144(259, false, true, Type.DH),
    FFDHE8192(260, false, true, Type.DH),

    // KEM
    MLKEM512(512, false, true, Type.KEM),
    MLKEM768(513, false, true, Type.KEM),
    MLKEM1024(514, false, true, Type.KEM),

    // ECC
    SECP256R1MLKEM768(4587, false, true, Type.ECC),
    X25519MLKEM768(4588, false, true, Type.ECC),
    ARBITRARY_EXPLICIT_PRIME_CURVES(65281, false, true, Type.ECC),
    ARBITRARY_EXPLICIT_CHAR2_CURVES(65282, false, true, Type.ECC);

    private static final Map<Integer, TlsSupportedGroup> VALUES = Arrays.stream(values())
            .collect(Collectors.toUnmodifiableMap(TlsSupportedGroup::id, Function.identity()));

    private static final List<TlsSupportedGroup> ALL = List.copyOf(VALUES.values());

    private static final List<TlsSupportedGroup> RECOMMENDED = Arrays.stream(TlsSupportedGroup.values())
            .filter(TlsSupportedGroup::recommended)
            .toList();

    private final int id;
    private final boolean recommended;
    private final boolean dtls;
    private final Type type;
    TlsSupportedGroup(int value, boolean recommended, boolean dtls, Type type) {
        this.id = value;
        this.recommended = recommended;
        this.dtls = dtls;
        this.type = type;
    }

    public static Optional<TlsSupportedGroup> of(int id) {
        return Optional.ofNullable(VALUES.get(id));
    }

    public static List<TlsSupportedGroup> recommendedGroups() {
        // FIXME: Return RECOMMENDED when KeyShare generation works
        var recommended = new ArrayList<>(RECOMMENDED);
        recommended.remove(X25519);
        recommended.addFirst(X25519);
        return recommended;
    }

    public static List<TlsSupportedGroup> supportedGroups() {
        return ALL;
    }

    public int id() {
        return id;
    }

    public boolean recommended() {
        return recommended;
    }

    public boolean dtls() {
        return dtls;
    }

    public Type type() {
        return type;
    }

    public enum Type {
        ECDH,
        DH,
        KEM,
        ECC
    }
}
