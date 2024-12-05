package it.auties.leap.tls;

import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

public final class TlsCipher {
    private static final ConcurrentMap<Integer, TlsCipher> CIPHERS = new ConcurrentHashMap<>();

    public static Optional<TlsCipher> of(int cipherId) {
        return Optional.ofNullable(CIPHERS.get(cipherId));
    }

    public static TlsCipher newTlsCipher(int id, TlsKeyExchangeType keyExchange, TlsAuthType auth, Type type, TlsHashType hashType, List<TlsVersion> versions, boolean recommended) {
        if(CIPHERS.containsKey(id)) {
            throw new IllegalArgumentException("A cipher with id %s was already registered".formatted(id));
        }
        
        var cipher = new TlsCipher(id, keyExchange, auth, type, hashType, versions, recommended);
        CIPHERS.put(id, cipher);
        return cipher;
    }

    //<editor-fold desc="Ciphers">
    private static final TlsCipher TLS_AES_128_CCM_8_SHA256 = newTlsCipher(0x1305, TlsKeyExchangeType.NULL, TlsAuthType.NULL, Type.AES_128_CCM_8, TlsHashType.SHA256, List.of(TlsVersion.TLS13), true);
    private static final TlsCipher TLS_AES_128_CCM_SHA256 = newTlsCipher(0x1304, TlsKeyExchangeType.NULL, TlsAuthType.NULL, Type.AES_128_CCM, TlsHashType.SHA256, List.of(TlsVersion.TLS13), true);
    private static final TlsCipher TLS_AES_128_GCM_SHA256 = newTlsCipher(0x1301, TlsKeyExchangeType.NULL, TlsAuthType.NULL, Type.AES_128_GCM, TlsHashType.SHA256, List.of(TlsVersion.TLS13), false);
    private static final TlsCipher TLS_AES_256_GCM_SHA384 = newTlsCipher(0x1302, TlsKeyExchangeType.NULL, TlsAuthType.NULL, Type.AES_256_GCM, TlsHashType.SHA384, List.of(TlsVersion.TLS13), false);
    private static final TlsCipher TLS_CHACHA20_POLY1305_SHA256 = newTlsCipher(0x1303, TlsKeyExchangeType.NULL, TlsAuthType.NULL, Type.CHACHA20_POLY1305, TlsHashType.SHA256, List.of(TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DH_ANON_EXPORT_WITH_DES40_CBC_SHA = newTlsCipher(0x0019, TlsKeyExchangeType.DH, TlsAuthType.ANON, Type.DES40_CBC, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DH_ANON_EXPORT_WITH_RC4_40_MD5 = newTlsCipher(0x0017, TlsKeyExchangeType.DH, TlsAuthType.ANON, Type.RC4_40, TlsHashType.MD5, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DH_ANON_WITH_3DES_EDE_CBC_SHA = newTlsCipher(0x001B, TlsKeyExchangeType.DH, TlsAuthType.ANON, Type.TRIPLE_DES_EDE_CBC, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DH_ANON_WITH_AES_128_CBC_SHA = newTlsCipher(0x0034, TlsKeyExchangeType.DH, TlsAuthType.ANON, Type.AES_128_CBC, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DH_ANON_WITH_AES_128_CBC_SHA256 = newTlsCipher(0x006C, TlsKeyExchangeType.DH, TlsAuthType.ANON, Type.AES_128_CBC, TlsHashType.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DH_ANON_WITH_AES_128_GCM_SHA256 = newTlsCipher(0x00A6, TlsKeyExchangeType.DH, TlsAuthType.ANON, Type.AES_128_GCM, TlsHashType.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DH_ANON_WITH_AES_256_CBC_SHA = newTlsCipher(0x003A, TlsKeyExchangeType.DH, TlsAuthType.ANON, Type.AES_256_CBC, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DH_ANON_WITH_AES_256_CBC_SHA256 = newTlsCipher(0x006D, TlsKeyExchangeType.DH, TlsAuthType.ANON, Type.AES_256_CBC, TlsHashType.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DH_ANON_WITH_AES_256_GCM_SHA384 = newTlsCipher(0x00A7, TlsKeyExchangeType.DH, TlsAuthType.ANON, Type.AES_256_GCM, TlsHashType.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DH_ANON_WITH_ARIA_128_CBC_SHA256 = newTlsCipher(0xC046, TlsKeyExchangeType.DH, TlsAuthType.ANON, Type.ARIA_128_CBC, TlsHashType.SHA256, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DH_ANON_WITH_ARIA_128_GCM_SHA256 = newTlsCipher(0xC05A, TlsKeyExchangeType.DH, TlsAuthType.ANON, Type.ARIA_128_GCM, TlsHashType.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DH_ANON_WITH_ARIA_256_CBC_SHA384 = newTlsCipher(0xC047, TlsKeyExchangeType.DH, TlsAuthType.ANON, Type.ARIA_256_CBC, TlsHashType.SHA384, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DH_ANON_WITH_ARIA_256_GCM_SHA384 = newTlsCipher(0xC05B, TlsKeyExchangeType.DH, TlsAuthType.ANON, Type.ARIA_256_GCM, TlsHashType.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DH_ANON_WITH_CAMELLIA_128_CBC_SHA = newTlsCipher(0x0046, TlsKeyExchangeType.DH, TlsAuthType.ANON, Type.CAMELLIA_128_CBC, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DH_ANON_WITH_CAMELLIA_128_CBC_SHA256 = newTlsCipher(0x00BF, TlsKeyExchangeType.DH, TlsAuthType.ANON, Type.CAMELLIA_128_CBC, TlsHashType.SHA256, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DH_ANON_WITH_CAMELLIA_128_GCM_SHA256 = newTlsCipher(0xC084, TlsKeyExchangeType.DH, TlsAuthType.ANON, Type.CAMELLIA_128_GCM, TlsHashType.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DH_ANON_WITH_CAMELLIA_256_CBC_SHA = newTlsCipher(0x0089, TlsKeyExchangeType.DH, TlsAuthType.ANON, Type.CAMELLIA_256_CBC, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DH_ANON_WITH_CAMELLIA_256_CBC_SHA256 = newTlsCipher(0x00C5, TlsKeyExchangeType.DH, TlsAuthType.ANON, Type.CAMELLIA_256_CBC, TlsHashType.SHA256, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DH_ANON_WITH_CAMELLIA_256_GCM_SHA384 = newTlsCipher(0xC085, TlsKeyExchangeType.DH, TlsAuthType.ANON, Type.CAMELLIA_256_GCM, TlsHashType.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DH_ANON_WITH_DES_CBC_SHA = newTlsCipher(0x001A, TlsKeyExchangeType.DH, TlsAuthType.ANON, Type.DES_CBC, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DH_ANON_WITH_RC4_128_MD5 = newTlsCipher(0x0018, TlsKeyExchangeType.DH, TlsAuthType.ANON, Type.RC4_128, TlsHashType.MD5, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DH_ANON_WITH_SEED_CBC_SHA = newTlsCipher(0x009B, TlsKeyExchangeType.DH, TlsAuthType.ANON, Type.SEED_CBC, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA = newTlsCipher(0x000B, TlsKeyExchangeType.DH, TlsAuthType.DSS, Type.DES40_CBC, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA = newTlsCipher(0x000D, TlsKeyExchangeType.DH, TlsAuthType.DSS, Type.TRIPLE_DES_EDE_CBC, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DH_DSS_WITH_AES_128_CBC_SHA = newTlsCipher(0x0030, TlsKeyExchangeType.DH, TlsAuthType.DSS, Type.AES_128_CBC, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DH_DSS_WITH_AES_128_CBC_SHA256 = newTlsCipher(0x003E, TlsKeyExchangeType.DH, TlsAuthType.DSS, Type.AES_128_CBC, TlsHashType.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DH_DSS_WITH_AES_128_GCM_SHA256 = newTlsCipher(0x00A4, TlsKeyExchangeType.DH, TlsAuthType.DSS, Type.AES_128_GCM, TlsHashType.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DH_DSS_WITH_AES_256_CBC_SHA = newTlsCipher(0x0036, TlsKeyExchangeType.DH, TlsAuthType.DSS, Type.AES_256_CBC, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DH_DSS_WITH_AES_256_CBC_SHA256 = newTlsCipher(0x0068, TlsKeyExchangeType.DH, TlsAuthType.DSS, Type.AES_256_CBC, TlsHashType.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DH_DSS_WITH_AES_256_GCM_SHA384 = newTlsCipher(0x00A5, TlsKeyExchangeType.DH, TlsAuthType.DSS, Type.AES_256_GCM, TlsHashType.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256 = newTlsCipher(0xC03E, TlsKeyExchangeType.DH, TlsAuthType.DSS, Type.ARIA_128_CBC, TlsHashType.SHA256, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256 = newTlsCipher(0xC058, TlsKeyExchangeType.DH, TlsAuthType.DSS, Type.ARIA_128_GCM, TlsHashType.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384 = newTlsCipher(0xC03F, TlsKeyExchangeType.DH, TlsAuthType.DSS, Type.ARIA_256_CBC, TlsHashType.SHA384, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384 = newTlsCipher(0xC059, TlsKeyExchangeType.DH, TlsAuthType.DSS, Type.ARIA_256_GCM, TlsHashType.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA = newTlsCipher(0x0042, TlsKeyExchangeType.DH, TlsAuthType.DSS, Type.CAMELLIA_128_CBC, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256 = newTlsCipher(0x00BB, TlsKeyExchangeType.DH, TlsAuthType.DSS, Type.CAMELLIA_128_CBC, TlsHashType.SHA256, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256 = newTlsCipher(0xC082, TlsKeyExchangeType.DH, TlsAuthType.DSS, Type.CAMELLIA_128_GCM, TlsHashType.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA = newTlsCipher(0x0085, TlsKeyExchangeType.DH, TlsAuthType.DSS, Type.CAMELLIA_256_CBC, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256 = newTlsCipher(0x00C1, TlsKeyExchangeType.DH, TlsAuthType.DSS, Type.CAMELLIA_256_CBC, TlsHashType.SHA256, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384 = newTlsCipher(0xC083, TlsKeyExchangeType.DH, TlsAuthType.DSS, Type.CAMELLIA_256_GCM, TlsHashType.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DH_DSS_WITH_DES_CBC_SHA = newTlsCipher(0x000C, TlsKeyExchangeType.DH, TlsAuthType.DSS, Type.DES_CBC, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DH_DSS_WITH_SEED_CBC_SHA = newTlsCipher(0x0097, TlsKeyExchangeType.DH, TlsAuthType.DSS, Type.SEED_CBC, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA = newTlsCipher(0x0011, TlsKeyExchangeType.DHE, TlsAuthType.DSS, Type.DES40_CBC, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA = newTlsCipher(0x0013, TlsKeyExchangeType.DHE, TlsAuthType.DSS, Type.TRIPLE_DES_EDE_CBC, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DHE_DSS_WITH_AES_128_CBC_SHA = newTlsCipher(0x0032, TlsKeyExchangeType.DHE, TlsAuthType.DSS, Type.AES_128_CBC, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DHE_DSS_WITH_AES_128_CBC_SHA256 = newTlsCipher(0x0040, TlsKeyExchangeType.DHE, TlsAuthType.DSS, Type.AES_128_CBC, TlsHashType.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DHE_DSS_WITH_AES_128_GCM_SHA256 = newTlsCipher(0x00A2, TlsKeyExchangeType.DHE, TlsAuthType.DSS, Type.AES_128_GCM, TlsHashType.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DHE_DSS_WITH_AES_256_CBC_SHA = newTlsCipher(0x0038, TlsKeyExchangeType.DHE, TlsAuthType.DSS, Type.AES_256_CBC, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DHE_DSS_WITH_AES_256_CBC_SHA256 = newTlsCipher(0x006A, TlsKeyExchangeType.DHE, TlsAuthType.DSS, Type.AES_256_CBC, TlsHashType.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DHE_DSS_WITH_AES_256_GCM_SHA384 = newTlsCipher(0x00A3, TlsKeyExchangeType.DHE, TlsAuthType.DSS, Type.AES_256_GCM, TlsHashType.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256 = newTlsCipher(0xC042, TlsKeyExchangeType.DHE, TlsAuthType.DSS, Type.ARIA_128_CBC, TlsHashType.SHA256, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256 = newTlsCipher(0xC056, TlsKeyExchangeType.DHE, TlsAuthType.DSS, Type.ARIA_128_GCM, TlsHashType.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384 = newTlsCipher(0xC043, TlsKeyExchangeType.DHE, TlsAuthType.DSS, Type.ARIA_256_CBC, TlsHashType.SHA384, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384 = newTlsCipher(0xC057, TlsKeyExchangeType.DHE, TlsAuthType.DSS, Type.ARIA_256_GCM, TlsHashType.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA = newTlsCipher(0x0044, TlsKeyExchangeType.DHE, TlsAuthType.DSS, Type.CAMELLIA_128_CBC, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256 = newTlsCipher(0x00BD, TlsKeyExchangeType.DHE, TlsAuthType.DSS, Type.CAMELLIA_128_CBC, TlsHashType.SHA256, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256 = newTlsCipher(0xC080, TlsKeyExchangeType.DHE, TlsAuthType.DSS, Type.CAMELLIA_128_GCM, TlsHashType.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA = newTlsCipher(0x0087, TlsKeyExchangeType.DHE, TlsAuthType.DSS, Type.CAMELLIA_256_CBC, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256 = newTlsCipher(0x00C3, TlsKeyExchangeType.DHE, TlsAuthType.DSS, Type.CAMELLIA_256_CBC, TlsHashType.SHA256, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384 = newTlsCipher(0xC081, TlsKeyExchangeType.DHE, TlsAuthType.DSS, Type.CAMELLIA_256_GCM, TlsHashType.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DHE_DSS_WITH_DES_CBC_SHA = newTlsCipher(0x0012, TlsKeyExchangeType.DHE, TlsAuthType.DSS, Type.DES_CBC, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DHE_DSS_WITH_SEED_CBC_SHA = newTlsCipher(0x0099, TlsKeyExchangeType.DHE, TlsAuthType.DSS, Type.SEED_CBC, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA = newTlsCipher(0x008F, TlsKeyExchangeType.DHE, TlsAuthType.PSK, Type.TRIPLE_DES_EDE_CBC, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DHE_PSK_WITH_AES_128_CBC_SHA = newTlsCipher(0x0090, TlsKeyExchangeType.DHE, TlsAuthType.PSK, Type.AES_128_CBC, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DHE_PSK_WITH_AES_128_CBC_SHA256 = newTlsCipher(0x00B2, TlsKeyExchangeType.DHE, TlsAuthType.PSK, Type.AES_128_CBC, TlsHashType.SHA256, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DHE_PSK_WITH_AES_128_CCM = newTlsCipher(0xC0A6, TlsKeyExchangeType.DHE, TlsAuthType.PSK, Type.AES_128_CCM, TlsHashType.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DHE_PSK_WITH_AES_128_GCM_SHA256 = newTlsCipher(0x00AA, TlsKeyExchangeType.DHE, TlsAuthType.PSK, Type.AES_128_GCM, TlsHashType.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DHE_PSK_WITH_AES_256_CBC_SHA = newTlsCipher(0x0091, TlsKeyExchangeType.DHE, TlsAuthType.PSK, Type.AES_256_CBC, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DHE_PSK_WITH_AES_256_CBC_SHA384 = newTlsCipher(0x00B3, TlsKeyExchangeType.DHE, TlsAuthType.PSK, Type.AES_256_CBC, TlsHashType.SHA384, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DHE_PSK_WITH_AES_256_CCM = newTlsCipher(0xC0A7, TlsKeyExchangeType.DHE, TlsAuthType.PSK, Type.AES_256_CCM, TlsHashType.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DHE_PSK_WITH_AES_256_GCM_SHA384 = newTlsCipher(0x00AB, TlsKeyExchangeType.DHE, TlsAuthType.PSK, Type.AES_256_GCM, TlsHashType.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256 = newTlsCipher(0xC066, TlsKeyExchangeType.DHE, TlsAuthType.PSK, Type.ARIA_128_CBC, TlsHashType.SHA256, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256 = newTlsCipher(0xC06C, TlsKeyExchangeType.DHE, TlsAuthType.PSK, Type.ARIA_128_GCM, TlsHashType.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384 = newTlsCipher(0xC067, TlsKeyExchangeType.DHE, TlsAuthType.PSK, Type.ARIA_256_CBC, TlsHashType.SHA384, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384 = newTlsCipher(0xC06D, TlsKeyExchangeType.DHE, TlsAuthType.PSK, Type.ARIA_256_GCM, TlsHashType.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 = newTlsCipher(0xC096, TlsKeyExchangeType.DHE, TlsAuthType.PSK, Type.CAMELLIA_128_CBC, TlsHashType.SHA256, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256 = newTlsCipher(0xC090, TlsKeyExchangeType.DHE, TlsAuthType.PSK, Type.CAMELLIA_128_GCM, TlsHashType.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 = newTlsCipher(0xC097, TlsKeyExchangeType.DHE, TlsAuthType.PSK, Type.CAMELLIA_256_CBC, TlsHashType.SHA384, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384 = newTlsCipher(0xC091, TlsKeyExchangeType.DHE, TlsAuthType.PSK, Type.CAMELLIA_256_GCM, TlsHashType.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256 = newTlsCipher(0xCCAD, TlsKeyExchangeType.DHE, TlsAuthType.PSK, Type.CHACHA20_POLY1305, TlsHashType.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DHE_PSK_WITH_NULL_SHA = newTlsCipher(0x002D, TlsKeyExchangeType.DHE, TlsAuthType.PSK, Type.NULL, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DHE_PSK_WITH_NULL_SHA256 = newTlsCipher(0x00B4, TlsKeyExchangeType.DHE, TlsAuthType.PSK, Type.NULL, TlsHashType.SHA256, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DHE_PSK_WITH_NULL_SHA384 = newTlsCipher(0x00B5, TlsKeyExchangeType.DHE, TlsAuthType.PSK, Type.NULL, TlsHashType.SHA384, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DHE_PSK_WITH_RC4_128_SHA = newTlsCipher(0x008E, TlsKeyExchangeType.DHE, TlsAuthType.PSK, Type.RC4_128, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA = newTlsCipher(0x0014, TlsKeyExchangeType.DHE, TlsAuthType.RSA, Type.DES40_CBC, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA = newTlsCipher(0x0016, TlsKeyExchangeType.DHE, TlsAuthType.RSA, Type.TRIPLE_DES_EDE_CBC, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DHE_RSA_WITH_AES_128_CBC_SHA = newTlsCipher(0x0033, TlsKeyExchangeType.DHE, TlsAuthType.RSA, Type.AES_128_CBC, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 = newTlsCipher(0x0067, TlsKeyExchangeType.DHE, TlsAuthType.RSA, Type.AES_128_CBC, TlsHashType.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DHE_RSA_WITH_AES_128_CCM = newTlsCipher(0xC09E, TlsKeyExchangeType.DHE, TlsAuthType.RSA, Type.AES_128_CCM, TlsHashType.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DHE_RSA_WITH_AES_128_CCM_8 = newTlsCipher(0xC0A2, TlsKeyExchangeType.DHE, TlsAuthType.RSA, Type.AES_128_CCM_8, TlsHashType.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 = newTlsCipher(0x009E, TlsKeyExchangeType.DHE, TlsAuthType.RSA, Type.AES_128_GCM, TlsHashType.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DHE_RSA_WITH_AES_256_CBC_SHA = newTlsCipher(0x0039, TlsKeyExchangeType.DHE, TlsAuthType.RSA, Type.AES_256_CBC, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 = newTlsCipher(0x006B, TlsKeyExchangeType.DHE, TlsAuthType.RSA, Type.AES_256_CBC, TlsHashType.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DHE_RSA_WITH_AES_256_CCM = newTlsCipher(0xC09F, TlsKeyExchangeType.DHE, TlsAuthType.RSA, Type.AES_256_CCM, TlsHashType.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DHE_RSA_WITH_AES_256_CCM_8 = newTlsCipher(0xC0A3, TlsKeyExchangeType.DHE, TlsAuthType.RSA, Type.AES_256_CCM_8, TlsHashType.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 = newTlsCipher(0x009F, TlsKeyExchangeType.DHE, TlsAuthType.RSA, Type.AES_256_GCM, TlsHashType.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256 = newTlsCipher(0xC044, TlsKeyExchangeType.DHE, TlsAuthType.RSA, Type.ARIA_128_CBC, TlsHashType.SHA256, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256 = newTlsCipher(0xC052, TlsKeyExchangeType.DHE, TlsAuthType.RSA, Type.ARIA_128_GCM, TlsHashType.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384 = newTlsCipher(0xC045, TlsKeyExchangeType.DHE, TlsAuthType.RSA, Type.ARIA_256_CBC, TlsHashType.SHA384, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384 = newTlsCipher(0xC053, TlsKeyExchangeType.DHE, TlsAuthType.RSA, Type.ARIA_256_GCM, TlsHashType.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA = newTlsCipher(0x0045, TlsKeyExchangeType.DHE, TlsAuthType.RSA, Type.CAMELLIA_128_CBC, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 = newTlsCipher(0x00BE, TlsKeyExchangeType.DHE, TlsAuthType.RSA, Type.CAMELLIA_128_CBC, TlsHashType.SHA256, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 = newTlsCipher(0xC07C, TlsKeyExchangeType.DHE, TlsAuthType.RSA, Type.CAMELLIA_128_GCM, TlsHashType.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA = newTlsCipher(0x0088, TlsKeyExchangeType.DHE, TlsAuthType.RSA, Type.CAMELLIA_256_CBC, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256 = newTlsCipher(0x00C4, TlsKeyExchangeType.DHE, TlsAuthType.RSA, Type.CAMELLIA_256_CBC, TlsHashType.SHA256, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 = newTlsCipher(0xC07D, TlsKeyExchangeType.DHE, TlsAuthType.RSA, Type.CAMELLIA_256_GCM, TlsHashType.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = newTlsCipher(0xCCAA, TlsKeyExchangeType.DHE, TlsAuthType.RSA, Type.CHACHA20_POLY1305, TlsHashType.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DHE_RSA_WITH_DES_CBC_SHA = newTlsCipher(0x0015, TlsKeyExchangeType.DHE, TlsAuthType.RSA, Type.DES_CBC, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DHE_RSA_WITH_SEED_CBC_SHA = newTlsCipher(0x009A, TlsKeyExchangeType.DHE, TlsAuthType.RSA, Type.SEED_CBC, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA = newTlsCipher(0x000E, TlsKeyExchangeType.DH, TlsAuthType.RSA, Type.DES40_CBC, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA = newTlsCipher(0x0010, TlsKeyExchangeType.DH, TlsAuthType.RSA, Type.TRIPLE_DES_EDE_CBC, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DH_RSA_WITH_AES_128_CBC_SHA = newTlsCipher(0x0031, TlsKeyExchangeType.DH, TlsAuthType.RSA, Type.AES_128_CBC, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DH_RSA_WITH_AES_128_CBC_SHA256 = newTlsCipher(0x003F, TlsKeyExchangeType.DH, TlsAuthType.RSA, Type.AES_128_CBC, TlsHashType.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DH_RSA_WITH_AES_128_GCM_SHA256 = newTlsCipher(0x00A0, TlsKeyExchangeType.DH, TlsAuthType.RSA, Type.AES_128_GCM, TlsHashType.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DH_RSA_WITH_AES_256_CBC_SHA = newTlsCipher(0x0037, TlsKeyExchangeType.DH, TlsAuthType.RSA, Type.AES_256_CBC, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DH_RSA_WITH_AES_256_CBC_SHA256 = newTlsCipher(0x0069, TlsKeyExchangeType.DH, TlsAuthType.RSA, Type.AES_256_CBC, TlsHashType.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DH_RSA_WITH_AES_256_GCM_SHA384 = newTlsCipher(0x00A1, TlsKeyExchangeType.DH, TlsAuthType.RSA, Type.AES_256_GCM, TlsHashType.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256 = newTlsCipher(0xC040, TlsKeyExchangeType.DH, TlsAuthType.RSA, Type.ARIA_128_CBC, TlsHashType.SHA256, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256 = newTlsCipher(0xC054, TlsKeyExchangeType.DH, TlsAuthType.RSA, Type.ARIA_128_GCM, TlsHashType.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384 = newTlsCipher(0xC041, TlsKeyExchangeType.DH, TlsAuthType.RSA, Type.ARIA_256_CBC, TlsHashType.SHA384, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384 = newTlsCipher(0xC055, TlsKeyExchangeType.DH, TlsAuthType.RSA, Type.ARIA_256_GCM, TlsHashType.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA = newTlsCipher(0x0043, TlsKeyExchangeType.DH, TlsAuthType.RSA, Type.CAMELLIA_128_CBC, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256 = newTlsCipher(0x00BC, TlsKeyExchangeType.DH, TlsAuthType.RSA, Type.CAMELLIA_128_CBC, TlsHashType.SHA256, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256 = newTlsCipher(0xC07E, TlsKeyExchangeType.DH, TlsAuthType.RSA, Type.CAMELLIA_128_GCM, TlsHashType.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA = newTlsCipher(0x0086, TlsKeyExchangeType.DH, TlsAuthType.RSA, Type.CAMELLIA_256_CBC, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256 = newTlsCipher(0x00C2, TlsKeyExchangeType.DH, TlsAuthType.RSA, Type.CAMELLIA_256_CBC, TlsHashType.SHA256, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384 = newTlsCipher(0xC07F, TlsKeyExchangeType.DH, TlsAuthType.RSA, Type.CAMELLIA_256_GCM, TlsHashType.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DH_RSA_WITH_DES_CBC_SHA = newTlsCipher(0x000F, TlsKeyExchangeType.DH, TlsAuthType.RSA, Type.DES_CBC, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_DH_RSA_WITH_SEED_CBC_SHA = newTlsCipher(0x0098, TlsKeyExchangeType.DH, TlsAuthType.RSA, Type.SEED_CBC, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_ECCPWD_WITH_AES_128_CCM_SHA256 = newTlsCipher(0xC0B2, TlsKeyExchangeType.ECCPWD, TlsAuthType.ECCPWD, Type.AES_128_CCM, TlsHashType.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13), true);
    private static final TlsCipher TLS_ECCPWD_WITH_AES_128_GCM_SHA256 = newTlsCipher(0xC0B0, TlsKeyExchangeType.ECCPWD, TlsAuthType.ECCPWD, Type.AES_128_GCM, TlsHashType.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_ECCPWD_WITH_AES_256_CCM_SHA384 = newTlsCipher(0xC0B3, TlsKeyExchangeType.ECCPWD, TlsAuthType.ECCPWD, Type.AES_256_CCM, TlsHashType.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13), true);
    private static final TlsCipher TLS_ECCPWD_WITH_AES_256_GCM_SHA384 = newTlsCipher(0xC0B1, TlsKeyExchangeType.ECCPWD, TlsAuthType.ECCPWD, Type.AES_256_GCM, TlsHashType.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_ECDH_ANON_WITH_3DES_EDE_CBC_SHA = newTlsCipher(0xC017, TlsKeyExchangeType.ECDH, TlsAuthType.ANON, Type.TRIPLE_DES_EDE_CBC, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_ECDH_ANON_WITH_AES_128_CBC_SHA = newTlsCipher(0xC018, TlsKeyExchangeType.ECDH, TlsAuthType.ANON, Type.AES_128_CBC, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_ECDH_ANON_WITH_AES_256_CBC_SHA = newTlsCipher(0xC019, TlsKeyExchangeType.ECDH, TlsAuthType.ANON, Type.AES_256_CBC, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_ECDH_ANON_WITH_NULL_SHA = newTlsCipher(0xC015, TlsKeyExchangeType.ECDH, TlsAuthType.ANON, Type.NULL, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_ECDH_ANON_WITH_RC4_128_SHA = newTlsCipher(0xC016, TlsKeyExchangeType.ECDH, TlsAuthType.ANON, Type.RC4_128, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA = newTlsCipher(0xC003, TlsKeyExchangeType.ECDH, TlsAuthType.ECDSA, Type.TRIPLE_DES_EDE_CBC, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA = newTlsCipher(0xC004, TlsKeyExchangeType.ECDH, TlsAuthType.ECDSA, Type.AES_128_CBC, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256 = newTlsCipher(0xC025, TlsKeyExchangeType.ECDH, TlsAuthType.ECDSA, Type.AES_128_CBC, TlsHashType.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256 = newTlsCipher(0xC02D, TlsKeyExchangeType.ECDH, TlsAuthType.ECDSA, Type.AES_128_GCM, TlsHashType.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA = newTlsCipher(0xC005, TlsKeyExchangeType.ECDH, TlsAuthType.ECDSA, Type.AES_256_CBC, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384 = newTlsCipher(0xC026, TlsKeyExchangeType.ECDH, TlsAuthType.ECDSA, Type.AES_256_CBC, TlsHashType.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384 = newTlsCipher(0xC02E, TlsKeyExchangeType.ECDH, TlsAuthType.ECDSA, Type.AES_256_GCM, TlsHashType.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256 = newTlsCipher(0xC04A, TlsKeyExchangeType.ECDH, TlsAuthType.ECDSA, Type.ARIA_128_CBC, TlsHashType.SHA256, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256 = newTlsCipher(0xC05E, TlsKeyExchangeType.ECDH, TlsAuthType.ECDSA, Type.ARIA_128_GCM, TlsHashType.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384 = newTlsCipher(0xC04B, TlsKeyExchangeType.ECDH, TlsAuthType.ECDSA, Type.ARIA_256_CBC, TlsHashType.SHA384, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384 = newTlsCipher(0xC05F, TlsKeyExchangeType.ECDH, TlsAuthType.ECDSA, Type.ARIA_256_GCM, TlsHashType.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 = newTlsCipher(0xC074, TlsKeyExchangeType.ECDH, TlsAuthType.ECDSA, Type.CAMELLIA_128_CBC, TlsHashType.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 = newTlsCipher(0xC088, TlsKeyExchangeType.ECDH, TlsAuthType.ECDSA, Type.CAMELLIA_128_GCM, TlsHashType.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 = newTlsCipher(0xC075, TlsKeyExchangeType.ECDH, TlsAuthType.ECDSA, Type.CAMELLIA_256_CBC, TlsHashType.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 = newTlsCipher(0xC089, TlsKeyExchangeType.ECDH, TlsAuthType.ECDSA, Type.CAMELLIA_256_GCM, TlsHashType.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_ECDH_ECDSA_WITH_NULL_SHA = newTlsCipher(0xC001, TlsKeyExchangeType.ECDH, TlsAuthType.ECDSA, Type.NULL, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_ECDH_ECDSA_WITH_RC4_128_SHA = newTlsCipher(0xC002, TlsKeyExchangeType.ECDH, TlsAuthType.ECDSA, Type.RC4_128, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA = newTlsCipher(0xC008, TlsKeyExchangeType.ECDHE, TlsAuthType.ECDSA, Type.TRIPLE_DES_EDE_CBC, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA = newTlsCipher(0xC009, TlsKeyExchangeType.ECDHE, TlsAuthType.ECDSA, Type.AES_128_CBC, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 = newTlsCipher(0xC023, TlsKeyExchangeType.ECDHE, TlsAuthType.ECDSA, Type.AES_128_CBC, TlsHashType.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_ECDHE_ECDSA_WITH_AES_128_CCM = newTlsCipher(0xC0AC, TlsKeyExchangeType.ECDHE, TlsAuthType.ECDSA, Type.AES_128_CCM, TlsHashType.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13), true);
    private static final TlsCipher TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 = newTlsCipher(0xC0AE, TlsKeyExchangeType.ECDHE, TlsAuthType.ECDSA, Type.AES_128_CCM_8, TlsHashType.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13), true);
    private static final TlsCipher TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = newTlsCipher(0xC02B, TlsKeyExchangeType.ECDHE, TlsAuthType.ECDSA, Type.AES_128_GCM, TlsHashType.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA = newTlsCipher(0xC00A, TlsKeyExchangeType.ECDHE, TlsAuthType.ECDSA, Type.AES_256_CBC, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 = newTlsCipher(0xC024, TlsKeyExchangeType.ECDHE, TlsAuthType.ECDSA, Type.AES_256_CBC, TlsHashType.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_ECDHE_ECDSA_WITH_AES_256_CCM = newTlsCipher(0xC0AD, TlsKeyExchangeType.ECDHE, TlsAuthType.ECDSA, Type.AES_256_CCM, TlsHashType.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13), true);
    private static final TlsCipher TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8 = newTlsCipher(0xC0AF, TlsKeyExchangeType.ECDHE, TlsAuthType.ECDSA, Type.AES_256_CCM_8, TlsHashType.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13), true);
    private static final TlsCipher TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = newTlsCipher(0xC02C, TlsKeyExchangeType.ECDHE, TlsAuthType.ECDSA, Type.AES_256_GCM, TlsHashType.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256 = newTlsCipher(0xC048, TlsKeyExchangeType.ECDHE, TlsAuthType.ECDSA, Type.ARIA_128_CBC, TlsHashType.SHA256, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256 = newTlsCipher(0xC05C, TlsKeyExchangeType.ECDHE, TlsAuthType.ECDSA, Type.ARIA_128_GCM, TlsHashType.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384 = newTlsCipher(0xC049, TlsKeyExchangeType.ECDHE, TlsAuthType.ECDSA, Type.ARIA_256_CBC, TlsHashType.SHA384, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384 = newTlsCipher(0xC05D, TlsKeyExchangeType.ECDHE, TlsAuthType.ECDSA, Type.ARIA_256_GCM, TlsHashType.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 = newTlsCipher(0xC072, TlsKeyExchangeType.ECDHE, TlsAuthType.ECDSA, Type.CAMELLIA_128_CBC, TlsHashType.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 = newTlsCipher(0xC086, TlsKeyExchangeType.ECDHE, TlsAuthType.ECDSA, Type.CAMELLIA_128_GCM, TlsHashType.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 = newTlsCipher(0xC073, TlsKeyExchangeType.ECDHE, TlsAuthType.ECDSA, Type.CAMELLIA_256_CBC, TlsHashType.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 = newTlsCipher(0xC087, TlsKeyExchangeType.ECDHE, TlsAuthType.ECDSA, Type.CAMELLIA_256_GCM, TlsHashType.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = newTlsCipher(0xCCA9, TlsKeyExchangeType.ECDHE, TlsAuthType.ECDSA, Type.CHACHA20_POLY1305, TlsHashType.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_ECDHE_ECDSA_WITH_NULL_SHA = newTlsCipher(0xC006, TlsKeyExchangeType.ECDHE, TlsAuthType.ECDSA, Type.NULL, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_ECDHE_ECDSA_WITH_RC4_128_SHA = newTlsCipher(0xC007, TlsKeyExchangeType.ECDHE, TlsAuthType.ECDSA, Type.RC4_128, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA = newTlsCipher(0xC034, TlsKeyExchangeType.ECDHE, TlsAuthType.PSK, Type.TRIPLE_DES_EDE_CBC, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA = newTlsCipher(0xC035, TlsKeyExchangeType.ECDHE, TlsAuthType.PSK, Type.AES_128_CBC, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256 = newTlsCipher(0xC037, TlsKeyExchangeType.ECDHE, TlsAuthType.PSK, Type.AES_128_CBC, TlsHashType.SHA256, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256 = newTlsCipher(0xD003, TlsKeyExchangeType.ECDHE, TlsAuthType.PSK, Type.AES_128_CCM_8, TlsHashType.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13), true);
    private static final TlsCipher TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256 = newTlsCipher(0xD005, TlsKeyExchangeType.ECDHE, TlsAuthType.PSK, Type.AES_128_CCM, TlsHashType.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13), true);
    private static final TlsCipher TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256 = newTlsCipher(0xD001, TlsKeyExchangeType.ECDHE, TlsAuthType.PSK, Type.AES_128_GCM, TlsHashType.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA = newTlsCipher(0xC036, TlsKeyExchangeType.ECDHE, TlsAuthType.PSK, Type.AES_256_CBC, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384 = newTlsCipher(0xC038, TlsKeyExchangeType.ECDHE, TlsAuthType.PSK, Type.AES_256_CBC, TlsHashType.SHA384, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384 = newTlsCipher(0xD002, TlsKeyExchangeType.ECDHE, TlsAuthType.PSK, Type.AES_256_GCM, TlsHashType.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256 = newTlsCipher(0xC070, TlsKeyExchangeType.ECDHE, TlsAuthType.PSK, Type.ARIA_128_CBC, TlsHashType.SHA256, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384 = newTlsCipher(0xC071, TlsKeyExchangeType.ECDHE, TlsAuthType.PSK, Type.ARIA_256_CBC, TlsHashType.SHA384, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 = newTlsCipher(0xC09A, TlsKeyExchangeType.ECDHE, TlsAuthType.PSK, Type.CAMELLIA_128_CBC, TlsHashType.SHA256, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 = newTlsCipher(0xC09B, TlsKeyExchangeType.ECDHE, TlsAuthType.PSK, Type.CAMELLIA_256_CBC, TlsHashType.SHA384, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256 = newTlsCipher(0xCCAC, TlsKeyExchangeType.ECDHE, TlsAuthType.PSK, Type.CHACHA20_POLY1305, TlsHashType.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_ECDHE_PSK_WITH_NULL_SHA = newTlsCipher(0xC039, TlsKeyExchangeType.ECDHE, TlsAuthType.PSK, Type.NULL, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_ECDHE_PSK_WITH_NULL_SHA256 = newTlsCipher(0xC03A, TlsKeyExchangeType.ECDHE, TlsAuthType.PSK, Type.NULL, TlsHashType.SHA256, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_ECDHE_PSK_WITH_NULL_SHA384 = newTlsCipher(0xC03B, TlsKeyExchangeType.ECDHE, TlsAuthType.PSK, Type.NULL, TlsHashType.SHA384, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_ECDHE_PSK_WITH_RC4_128_SHA = newTlsCipher(0xC033, TlsKeyExchangeType.ECDHE, TlsAuthType.PSK, Type.RC4_128, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA = newTlsCipher(0xC012, TlsKeyExchangeType.ECDHE, TlsAuthType.RSA, Type.TRIPLE_DES_EDE_CBC, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA = newTlsCipher(0xC013, TlsKeyExchangeType.ECDHE, TlsAuthType.RSA, Type.AES_128_CBC, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 = newTlsCipher(0xC027, TlsKeyExchangeType.ECDHE, TlsAuthType.RSA, Type.AES_128_CBC, TlsHashType.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = newTlsCipher(0xC02F, TlsKeyExchangeType.ECDHE, TlsAuthType.RSA, Type.AES_128_GCM, TlsHashType.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13), true);
    private static final TlsCipher TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA = newTlsCipher(0xC014, TlsKeyExchangeType.ECDHE, TlsAuthType.RSA, Type.AES_256_CBC, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 = newTlsCipher(0xC028, TlsKeyExchangeType.ECDHE, TlsAuthType.RSA, Type.AES_256_CBC, TlsHashType.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = newTlsCipher(0xC030, TlsKeyExchangeType.ECDHE, TlsAuthType.RSA, Type.AES_256_GCM, TlsHashType.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13), true);
    private static final TlsCipher TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256 = newTlsCipher(0xC04C, TlsKeyExchangeType.ECDHE, TlsAuthType.RSA, Type.ARIA_128_CBC, TlsHashType.SHA256, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256 = newTlsCipher(0xC060, TlsKeyExchangeType.ECDHE, TlsAuthType.RSA, Type.ARIA_128_GCM, TlsHashType.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13), true);
    private static final TlsCipher TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384 = newTlsCipher(0xC04D, TlsKeyExchangeType.ECDHE, TlsAuthType.RSA, Type.ARIA_256_CBC, TlsHashType.SHA384, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384 = newTlsCipher(0xC061, TlsKeyExchangeType.ECDHE, TlsAuthType.RSA, Type.ARIA_256_GCM, TlsHashType.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13), true);
    private static final TlsCipher TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 = newTlsCipher(0xC076, TlsKeyExchangeType.ECDHE, TlsAuthType.RSA, Type.CAMELLIA_128_CBC, TlsHashType.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 = newTlsCipher(0xC08A, TlsKeyExchangeType.ECDHE, TlsAuthType.RSA, Type.CAMELLIA_128_GCM, TlsHashType.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13), true);
    private static final TlsCipher TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384 = newTlsCipher(0xC077, TlsKeyExchangeType.ECDHE, TlsAuthType.RSA, Type.CAMELLIA_256_CBC, TlsHashType.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 = newTlsCipher(0xC08B, TlsKeyExchangeType.ECDHE, TlsAuthType.RSA, Type.CAMELLIA_256_GCM, TlsHashType.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13), true);
    private static final TlsCipher TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = newTlsCipher(0xCCA8, TlsKeyExchangeType.ECDHE, TlsAuthType.RSA, Type.CHACHA20_POLY1305, TlsHashType.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13), true);
    private static final TlsCipher TLS_ECDHE_RSA_WITH_NULL_SHA = newTlsCipher(0xC010, TlsKeyExchangeType.ECDHE, TlsAuthType.RSA, Type.NULL, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_ECDHE_RSA_WITH_RC4_128_SHA = newTlsCipher(0xC011, TlsKeyExchangeType.ECDHE, TlsAuthType.RSA, Type.RC4_128, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA = newTlsCipher(0xC00D, TlsKeyExchangeType.ECDH, TlsAuthType.RSA, Type.TRIPLE_DES_EDE_CBC, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_ECDH_RSA_WITH_AES_128_CBC_SHA = newTlsCipher(0xC00E, TlsKeyExchangeType.ECDH, TlsAuthType.RSA, Type.AES_128_CBC, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256 = newTlsCipher(0xC029, TlsKeyExchangeType.ECDH, TlsAuthType.RSA, Type.AES_128_CBC, TlsHashType.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256 = newTlsCipher(0xC031, TlsKeyExchangeType.ECDH, TlsAuthType.RSA, Type.AES_128_GCM, TlsHashType.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_ECDH_RSA_WITH_AES_256_CBC_SHA = newTlsCipher(0xC00F, TlsKeyExchangeType.ECDH, TlsAuthType.RSA, Type.AES_256_CBC, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384 = newTlsCipher(0xC02A, TlsKeyExchangeType.ECDH, TlsAuthType.RSA, Type.AES_256_CBC, TlsHashType.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384 = newTlsCipher(0xC032, TlsKeyExchangeType.ECDH, TlsAuthType.RSA, Type.AES_256_GCM, TlsHashType.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256 = newTlsCipher(0xC04E, TlsKeyExchangeType.ECDH, TlsAuthType.RSA, Type.ARIA_128_CBC, TlsHashType.SHA256, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256 = newTlsCipher(0xC062, TlsKeyExchangeType.ECDH, TlsAuthType.RSA, Type.ARIA_128_GCM, TlsHashType.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384 = newTlsCipher(0xC04F, TlsKeyExchangeType.ECDH, TlsAuthType.RSA, Type.ARIA_256_CBC, TlsHashType.SHA384, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384 = newTlsCipher(0xC063, TlsKeyExchangeType.ECDH, TlsAuthType.RSA, Type.ARIA_256_GCM, TlsHashType.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256 = newTlsCipher(0xC078, TlsKeyExchangeType.ECDH, TlsAuthType.RSA, Type.CAMELLIA_128_CBC, TlsHashType.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256 = newTlsCipher(0xC08C, TlsKeyExchangeType.ECDH, TlsAuthType.RSA, Type.CAMELLIA_128_GCM, TlsHashType.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384 = newTlsCipher(0xC079, TlsKeyExchangeType.ECDH, TlsAuthType.RSA, Type.CAMELLIA_256_CBC, TlsHashType.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384 = newTlsCipher(0xC08D, TlsKeyExchangeType.ECDH, TlsAuthType.RSA, Type.CAMELLIA_256_GCM, TlsHashType.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_ECDH_RSA_WITH_NULL_SHA = newTlsCipher(0xC00B, TlsKeyExchangeType.ECDH, TlsAuthType.RSA, Type.NULL, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_ECDH_RSA_WITH_RC4_128_SHA = newTlsCipher(0xC00C, TlsKeyExchangeType.ECDH, TlsAuthType.RSA, Type.RC4_128, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_GOSTR341112_256_WITH_28147_CNT_IMIT = newTlsCipher(0xC102, TlsKeyExchangeType.GOSTR341112_256, TlsAuthType.GOSTR341012, Type.GOST_28147_CNT, TlsHashType.GOSTR341112_256, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC = newTlsCipher(0xC100, TlsKeyExchangeType.GOSTR341112_256, TlsAuthType.GOSTR341012, Type.KUZNYECHIK_CTR, TlsHashType.GOSTR341112_256, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L = newTlsCipher(0xC103, TlsKeyExchangeType.ECDHE, TlsAuthType.NULL, Type.KUZNYECHIK_MGM_L, TlsHashType.NULL, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S = newTlsCipher(0xC105, TlsKeyExchangeType.ECDHE, TlsAuthType.NULL, Type.KUZNYECHIK_MGM_S, TlsHashType.NULL, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC = newTlsCipher(0xC101, TlsKeyExchangeType.GOSTR341112_256, TlsAuthType.GOSTR341012, Type.MAGMA_CTR, TlsHashType.GOSTR341112_256, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_GOSTR341112_256_WITH_MAGMA_MGM_L = newTlsCipher(0xC104, TlsKeyExchangeType.ECDHE, TlsAuthType.NULL, Type.MAGMA_MGM_L, TlsHashType.NULL, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_GOSTR341112_256_WITH_MAGMA_MGM_S = newTlsCipher(0xC106, TlsKeyExchangeType.ECDHE, TlsAuthType.NULL, Type.MAGMA_MGM_S, TlsHashType.NULL, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5 = newTlsCipher(0x0029, TlsKeyExchangeType.KRB5, TlsAuthType.KRB5, Type.DES_CBC_40, TlsHashType.MD5, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA = newTlsCipher(0x0026, TlsKeyExchangeType.KRB5, TlsAuthType.KRB5, Type.DES_CBC_40, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5 = newTlsCipher(0x002A, TlsKeyExchangeType.KRB5, TlsAuthType.KRB5, Type.RC2_CBC_40, TlsHashType.MD5, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA = newTlsCipher(0x0027, TlsKeyExchangeType.KRB5, TlsAuthType.KRB5, Type.RC2_CBC_40, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_KRB5_EXPORT_WITH_RC4_40_MD5 = newTlsCipher(0x002B, TlsKeyExchangeType.KRB5, TlsAuthType.KRB5, Type.RC4_40, TlsHashType.MD5, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_KRB5_EXPORT_WITH_RC4_40_SHA = newTlsCipher(0x0028, TlsKeyExchangeType.KRB5, TlsAuthType.KRB5, Type.RC4_40, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_KRB5_WITH_3DES_EDE_CBC_MD5 = newTlsCipher(0x0023, TlsKeyExchangeType.KRB5, TlsAuthType.KRB5, Type.TRIPLE_DES_EDE_CBC, TlsHashType.MD5, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_KRB5_WITH_3DES_EDE_CBC_SHA = newTlsCipher(0x001F, TlsKeyExchangeType.KRB5, TlsAuthType.KRB5, Type.TRIPLE_DES_EDE_CBC, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_KRB5_WITH_DES_CBC_MD5 = newTlsCipher(0x0022, TlsKeyExchangeType.KRB5, TlsAuthType.KRB5, Type.DES_CBC, TlsHashType.MD5, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_KRB5_WITH_DES_CBC_SHA = newTlsCipher(0x001E, TlsKeyExchangeType.KRB5, TlsAuthType.KRB5, Type.DES_CBC, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_KRB5_WITH_IDEA_CBC_MD5 = newTlsCipher(0x0025, TlsKeyExchangeType.KRB5, TlsAuthType.KRB5, Type.IDEA_CBC, TlsHashType.MD5, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_KRB5_WITH_IDEA_CBC_SHA = newTlsCipher(0x0021, TlsKeyExchangeType.KRB5, TlsAuthType.KRB5, Type.IDEA_CBC, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_KRB5_WITH_RC4_128_MD5 = newTlsCipher(0x0024, TlsKeyExchangeType.KRB5, TlsAuthType.KRB5, Type.RC4_128, TlsHashType.MD5, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_KRB5_WITH_RC4_128_SHA = newTlsCipher(0x0020, TlsKeyExchangeType.KRB5, TlsAuthType.KRB5, Type.RC4_128, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_NULL_WITH_NULL_NULL = newTlsCipher(0x0000, TlsKeyExchangeType.NULL, TlsAuthType.NULL, Type.NULL, TlsHashType.NULL, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_PSK_DHE_WITH_AES_128_CCM_8 = newTlsCipher(0xC0AA, TlsKeyExchangeType.DHE, TlsAuthType.PSK, Type.AES_128_CCM_8, TlsHashType.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_PSK_DHE_WITH_AES_256_CCM_8 = newTlsCipher(0xC0AB, TlsKeyExchangeType.DHE, TlsAuthType.PSK, Type.AES_256_CCM_8, TlsHashType.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_PSK_WITH_3DES_EDE_CBC_SHA = newTlsCipher(0x008B, TlsKeyExchangeType.PSK, TlsAuthType.PSK, Type.TRIPLE_DES_EDE_CBC, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_PSK_WITH_AES_128_CBC_SHA = newTlsCipher(0x008C, TlsKeyExchangeType.PSK, TlsAuthType.PSK, Type.AES_128_CBC, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_PSK_WITH_AES_128_CBC_SHA256 = newTlsCipher(0x00AE, TlsKeyExchangeType.PSK, TlsAuthType.PSK, Type.AES_128_CBC, TlsHashType.SHA256, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_PSK_WITH_AES_128_CCM = newTlsCipher(0xC0A4, TlsKeyExchangeType.PSK, TlsAuthType.PSK, Type.AES_128_CCM, TlsHashType.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_PSK_WITH_AES_128_CCM_8 = newTlsCipher(0xC0A8, TlsKeyExchangeType.PSK, TlsAuthType.PSK, Type.AES_128_CCM_8, TlsHashType.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_PSK_WITH_AES_128_GCM_SHA256 = newTlsCipher(0x00A8, TlsKeyExchangeType.PSK, TlsAuthType.PSK, Type.AES_128_GCM, TlsHashType.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_PSK_WITH_AES_256_CBC_SHA = newTlsCipher(0x008D, TlsKeyExchangeType.PSK, TlsAuthType.PSK, Type.AES_256_CBC, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_PSK_WITH_AES_256_CBC_SHA384 = newTlsCipher(0x00AF, TlsKeyExchangeType.PSK, TlsAuthType.PSK, Type.AES_256_CBC, TlsHashType.SHA384, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_PSK_WITH_AES_256_CCM = newTlsCipher(0xC0A5, TlsKeyExchangeType.PSK, TlsAuthType.PSK, Type.AES_256_CCM, TlsHashType.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_PSK_WITH_AES_256_CCM_8 = newTlsCipher(0xC0A9, TlsKeyExchangeType.PSK, TlsAuthType.PSK, Type.AES_256_CCM_8, TlsHashType.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_PSK_WITH_AES_256_GCM_SHA384 = newTlsCipher(0x00A9, TlsKeyExchangeType.PSK, TlsAuthType.PSK, Type.AES_256_GCM, TlsHashType.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_PSK_WITH_ARIA_128_CBC_SHA256 = newTlsCipher(0xC064, TlsKeyExchangeType.PSK, TlsAuthType.PSK, Type.ARIA_128_CBC, TlsHashType.SHA256, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_PSK_WITH_ARIA_128_GCM_SHA256 = newTlsCipher(0xC06A, TlsKeyExchangeType.PSK, TlsAuthType.PSK, Type.ARIA_128_GCM, TlsHashType.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_PSK_WITH_ARIA_256_CBC_SHA384 = newTlsCipher(0xC065, TlsKeyExchangeType.PSK, TlsAuthType.PSK, Type.ARIA_256_CBC, TlsHashType.SHA384, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_PSK_WITH_ARIA_256_GCM_SHA384 = newTlsCipher(0xC06B, TlsKeyExchangeType.PSK, TlsAuthType.PSK, Type.ARIA_256_GCM, TlsHashType.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256 = newTlsCipher(0xC094, TlsKeyExchangeType.PSK, TlsAuthType.PSK, Type.CAMELLIA_128_CBC, TlsHashType.SHA256, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256 = newTlsCipher(0xC08E, TlsKeyExchangeType.PSK, TlsAuthType.PSK, Type.CAMELLIA_128_GCM, TlsHashType.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384 = newTlsCipher(0xC095, TlsKeyExchangeType.PSK, TlsAuthType.PSK, Type.CAMELLIA_256_CBC, TlsHashType.SHA384, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384 = newTlsCipher(0xC08F, TlsKeyExchangeType.PSK, TlsAuthType.PSK, Type.CAMELLIA_256_GCM, TlsHashType.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_PSK_WITH_CHACHA20_POLY1305_SHA256 = newTlsCipher(0xCCAB, TlsKeyExchangeType.PSK, TlsAuthType.PSK, Type.CHACHA20_POLY1305, TlsHashType.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_PSK_WITH_NULL_SHA = newTlsCipher(0x002C, TlsKeyExchangeType.PSK, TlsAuthType.PSK, Type.NULL, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_PSK_WITH_NULL_SHA256 = newTlsCipher(0x00B0, TlsKeyExchangeType.PSK, TlsAuthType.PSK, Type.NULL, TlsHashType.SHA256, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_PSK_WITH_NULL_SHA384 = newTlsCipher(0x00B1, TlsKeyExchangeType.PSK, TlsAuthType.PSK, Type.NULL, TlsHashType.SHA384, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_PSK_WITH_RC4_128_SHA = newTlsCipher(0x008A, TlsKeyExchangeType.PSK, TlsAuthType.PSK, Type.RC4_128, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_RSA_EXPORT_WITH_DES40_CBC_SHA = newTlsCipher(0x0008, TlsKeyExchangeType.RSA, TlsAuthType.RSA, Type.DES40_CBC, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5 = newTlsCipher(0x0006, TlsKeyExchangeType.RSA, TlsAuthType.RSA, Type.RC2_CBC_40, TlsHashType.MD5, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_RSA_EXPORT_WITH_RC4_40_MD5 = newTlsCipher(0x0003, TlsKeyExchangeType.RSA, TlsAuthType.RSA, Type.RC4_40, TlsHashType.MD5, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA = newTlsCipher(0x0093, TlsKeyExchangeType.RSA, TlsAuthType.PSK, Type.TRIPLE_DES_EDE_CBC, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_RSA_PSK_WITH_AES_128_CBC_SHA = newTlsCipher(0x0094, TlsKeyExchangeType.RSA, TlsAuthType.PSK, Type.AES_128_CBC, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_RSA_PSK_WITH_AES_128_CBC_SHA256 = newTlsCipher(0x00B6, TlsKeyExchangeType.RSA, TlsAuthType.PSK, Type.AES_128_CBC, TlsHashType.SHA256, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_RSA_PSK_WITH_AES_128_GCM_SHA256 = newTlsCipher(0x00AC, TlsKeyExchangeType.RSA, TlsAuthType.PSK, Type.AES_128_GCM, TlsHashType.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_RSA_PSK_WITH_AES_256_CBC_SHA = newTlsCipher(0x0095, TlsKeyExchangeType.RSA, TlsAuthType.PSK, Type.AES_256_CBC, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_RSA_PSK_WITH_AES_256_CBC_SHA384 = newTlsCipher(0x00B7, TlsKeyExchangeType.RSA, TlsAuthType.PSK, Type.AES_256_CBC, TlsHashType.SHA384, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_RSA_PSK_WITH_AES_256_GCM_SHA384 = newTlsCipher(0x00AD, TlsKeyExchangeType.RSA, TlsAuthType.PSK, Type.AES_256_GCM, TlsHashType.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256 = newTlsCipher(0xC068, TlsKeyExchangeType.RSA, TlsAuthType.PSK, Type.ARIA_128_CBC, TlsHashType.SHA256, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256 = newTlsCipher(0xC06E, TlsKeyExchangeType.RSA, TlsAuthType.PSK, Type.ARIA_128_GCM, TlsHashType.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384 = newTlsCipher(0xC069, TlsKeyExchangeType.RSA, TlsAuthType.PSK, Type.ARIA_256_CBC, TlsHashType.SHA384, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384 = newTlsCipher(0xC06F, TlsKeyExchangeType.RSA, TlsAuthType.PSK, Type.ARIA_256_GCM, TlsHashType.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256 = newTlsCipher(0xC098, TlsKeyExchangeType.RSA, TlsAuthType.PSK, Type.CAMELLIA_128_CBC, TlsHashType.SHA256, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256 = newTlsCipher(0xC092, TlsKeyExchangeType.RSA, TlsAuthType.PSK, Type.CAMELLIA_128_GCM, TlsHashType.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384 = newTlsCipher(0xC099, TlsKeyExchangeType.RSA, TlsAuthType.PSK, Type.CAMELLIA_256_CBC, TlsHashType.SHA384, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384 = newTlsCipher(0xC093, TlsKeyExchangeType.RSA, TlsAuthType.PSK, Type.CAMELLIA_256_GCM, TlsHashType.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256 = newTlsCipher(0xCCAE, TlsKeyExchangeType.RSA, TlsAuthType.PSK, Type.CHACHA20_POLY1305, TlsHashType.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_RSA_PSK_WITH_NULL_SHA = newTlsCipher(0x002E, TlsKeyExchangeType.RSA, TlsAuthType.PSK, Type.NULL, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_RSA_PSK_WITH_NULL_SHA256 = newTlsCipher(0x00B8, TlsKeyExchangeType.RSA, TlsAuthType.PSK, Type.NULL, TlsHashType.SHA256, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_RSA_PSK_WITH_NULL_SHA384 = newTlsCipher(0x00B9, TlsKeyExchangeType.RSA, TlsAuthType.PSK, Type.NULL, TlsHashType.SHA384, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_RSA_PSK_WITH_RC4_128_SHA = newTlsCipher(0x0092, TlsKeyExchangeType.RSA, TlsAuthType.PSK, Type.RC4_128, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_RSA_WITH_3DES_EDE_CBC_SHA = newTlsCipher(0x000A, TlsKeyExchangeType.RSA, TlsAuthType.RSA, Type.TRIPLE_DES_EDE_CBC, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_RSA_WITH_AES_128_CBC_SHA = newTlsCipher(0x002F, TlsKeyExchangeType.RSA, TlsAuthType.RSA, Type.AES_128_CBC, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_RSA_WITH_AES_128_CBC_SHA256 = newTlsCipher(0x003C, TlsKeyExchangeType.RSA, TlsAuthType.RSA, Type.AES_128_CBC, TlsHashType.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_RSA_WITH_AES_128_CCM = newTlsCipher(0xC09C, TlsKeyExchangeType.RSA, TlsAuthType.RSA, Type.AES_128_CCM, TlsHashType.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_RSA_WITH_AES_128_CCM_8 = newTlsCipher(0xC0A0, TlsKeyExchangeType.RSA, TlsAuthType.RSA, Type.AES_128_CCM_8, TlsHashType.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_RSA_WITH_AES_128_GCM_SHA256 = newTlsCipher(0x009C, TlsKeyExchangeType.RSA, TlsAuthType.RSA, Type.AES_128_GCM, TlsHashType.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_RSA_WITH_AES_256_CBC_SHA = newTlsCipher(0x0035, TlsKeyExchangeType.RSA, TlsAuthType.RSA, Type.AES_256_CBC, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_RSA_WITH_AES_256_CBC_SHA256 = newTlsCipher(0x003D, TlsKeyExchangeType.RSA, TlsAuthType.RSA, Type.AES_256_CBC, TlsHashType.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_RSA_WITH_AES_256_CCM = newTlsCipher(0xC09D, TlsKeyExchangeType.RSA, TlsAuthType.RSA, Type.AES_256_CCM, TlsHashType.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_RSA_WITH_AES_256_CCM_8 = newTlsCipher(0xC0A1, TlsKeyExchangeType.RSA, TlsAuthType.RSA, Type.AES_256_CCM_8, TlsHashType.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_RSA_WITH_AES_256_GCM_SHA384 = newTlsCipher(0x009D, TlsKeyExchangeType.RSA, TlsAuthType.RSA, Type.AES_256_GCM, TlsHashType.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_RSA_WITH_ARIA_128_CBC_SHA256 = newTlsCipher(0xC03C, TlsKeyExchangeType.RSA, TlsAuthType.RSA, Type.ARIA_128_CBC, TlsHashType.SHA256, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_RSA_WITH_ARIA_128_GCM_SHA256 = newTlsCipher(0xC050, TlsKeyExchangeType.RSA, TlsAuthType.RSA, Type.ARIA_128_GCM, TlsHashType.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_RSA_WITH_ARIA_256_CBC_SHA384 = newTlsCipher(0xC03D, TlsKeyExchangeType.RSA, TlsAuthType.RSA, Type.ARIA_256_CBC, TlsHashType.SHA384, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_RSA_WITH_ARIA_256_GCM_SHA384 = newTlsCipher(0xC051, TlsKeyExchangeType.RSA, TlsAuthType.RSA, Type.ARIA_256_GCM, TlsHashType.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_RSA_WITH_CAMELLIA_128_CBC_SHA = newTlsCipher(0x0041, TlsKeyExchangeType.RSA, TlsAuthType.RSA, Type.CAMELLIA_128_CBC, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256 = newTlsCipher(0x00BA, TlsKeyExchangeType.RSA, TlsAuthType.RSA, Type.CAMELLIA_128_CBC, TlsHashType.SHA256, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256 = newTlsCipher(0xC07A, TlsKeyExchangeType.RSA, TlsAuthType.RSA, Type.CAMELLIA_128_GCM, TlsHashType.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_RSA_WITH_CAMELLIA_256_CBC_SHA = newTlsCipher(0x0084, TlsKeyExchangeType.RSA, TlsAuthType.RSA, Type.CAMELLIA_256_CBC, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256 = newTlsCipher(0x00C0, TlsKeyExchangeType.RSA, TlsAuthType.RSA, Type.CAMELLIA_256_CBC, TlsHashType.SHA256, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384 = newTlsCipher(0xC07B, TlsKeyExchangeType.RSA, TlsAuthType.RSA, Type.CAMELLIA_256_GCM, TlsHashType.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_RSA_WITH_DES_CBC_SHA = newTlsCipher(0x0009, TlsKeyExchangeType.RSA, TlsAuthType.RSA, Type.DES_CBC, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_RSA_WITH_IDEA_CBC_SHA = newTlsCipher(0x0007, TlsKeyExchangeType.RSA, TlsAuthType.RSA, Type.IDEA_CBC, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_RSA_WITH_NULL_MD5 = newTlsCipher(0x0001, TlsKeyExchangeType.RSA, TlsAuthType.RSA, Type.NULL, TlsHashType.MD5, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_RSA_WITH_NULL_SHA = newTlsCipher(0x0002, TlsKeyExchangeType.RSA, TlsAuthType.RSA, Type.NULL, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_RSA_WITH_NULL_SHA256 = newTlsCipher(0x003B, TlsKeyExchangeType.RSA, TlsAuthType.RSA, Type.NULL, TlsHashType.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_RSA_WITH_RC4_128_MD5 = newTlsCipher(0x0004, TlsKeyExchangeType.RSA, TlsAuthType.RSA, Type.RC4_128, TlsHashType.MD5, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_RSA_WITH_RC4_128_SHA = newTlsCipher(0x0005, TlsKeyExchangeType.RSA, TlsAuthType.RSA, Type.RC4_128, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_RSA_WITH_SEED_CBC_SHA = newTlsCipher(0x0096, TlsKeyExchangeType.RSA, TlsAuthType.RSA, Type.SEED_CBC, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_SHA256_SHA256 = newTlsCipher(0xC0B4, TlsKeyExchangeType.NULL, TlsAuthType.SHA256, Type.NULL, TlsHashType.SHA256, List.of(TlsVersion.TLS13), false);
    private static final TlsCipher TLS_SHA384_SHA384 = newTlsCipher(0xC0B5, TlsKeyExchangeType.NULL, TlsAuthType.SHA384, Type.NULL, TlsHashType.SHA384, List.of(TlsVersion.TLS13), false);
    private static final TlsCipher TLS_SM4_CCM_SM3 = newTlsCipher(0x00C7, TlsKeyExchangeType.NULL, TlsAuthType.NULL, Type.SM4_CCM, TlsHashType.SM3, List.of(TlsVersion.TLS13), false);
    private static final TlsCipher TLS_SM4_GCM_SM3 = newTlsCipher(0x00C6, TlsKeyExchangeType.NULL, TlsAuthType.NULL, Type.SM4_GCM, TlsHashType.SM3, List.of(TlsVersion.TLS13), false);
    private static final TlsCipher TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA = newTlsCipher(0xC01C, TlsKeyExchangeType.SRP, TlsAuthType.SHA_DSS, Type.TRIPLE_DES_EDE_CBC, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA = newTlsCipher(0xC01F, TlsKeyExchangeType.SRP, TlsAuthType.SHA_DSS, Type.AES_128_CBC, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA = newTlsCipher(0xC022, TlsKeyExchangeType.SRP, TlsAuthType.SHA_DSS, Type.AES_256_CBC, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA = newTlsCipher(0xC01B, TlsKeyExchangeType.SRP, TlsAuthType.SHA_RSA, Type.TRIPLE_DES_EDE_CBC, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA = newTlsCipher(0xC01E, TlsKeyExchangeType.SRP, TlsAuthType.SHA_RSA, Type.AES_128_CBC, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA = newTlsCipher(0xC021, TlsKeyExchangeType.SRP, TlsAuthType.SHA_RSA, Type.AES_256_CBC, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA = newTlsCipher(0xC01A, TlsKeyExchangeType.SRP, TlsAuthType.SHA, Type.TRIPLE_DES_EDE_CBC, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_SRP_SHA_WITH_AES_128_CBC_SHA = newTlsCipher(0xC01D, TlsKeyExchangeType.SRP, TlsAuthType.SHA, Type.AES_128_CBC, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher TLS_SRP_SHA_WITH_AES_256_CBC_SHA = newTlsCipher(0xC020, TlsKeyExchangeType.SRP, TlsAuthType.SHA, Type.AES_256_CBC, TlsHashType.SHA1, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13), false);
    private static final TlsCipher[] TLS_GREASE = new TlsCipher[]{
            newTlsCipher(0x0A0A, TlsKeyExchangeType.NULL, TlsAuthType.NULL, Type.NULL, TlsHashType.NULL, List.of(TlsVersion.TLS13), true),
            newTlsCipher(0x0A1A, TlsKeyExchangeType.NULL, TlsAuthType.NULL, Type.NULL, TlsHashType.NULL, List.of(TlsVersion.TLS13), true),
            newTlsCipher(0x0A2A, TlsKeyExchangeType.NULL, TlsAuthType.NULL, Type.NULL, TlsHashType.NULL, List.of(TlsVersion.TLS13), true),
            newTlsCipher(0x0A3A, TlsKeyExchangeType.NULL, TlsAuthType.NULL, Type.NULL, TlsHashType.NULL, List.of(TlsVersion.TLS13), true),
            newTlsCipher(0x0A4A, TlsKeyExchangeType.NULL, TlsAuthType.NULL, Type.NULL, TlsHashType.NULL, List.of(TlsVersion.TLS13), true),
            newTlsCipher(0x0A5A, TlsKeyExchangeType.NULL, TlsAuthType.NULL, Type.NULL, TlsHashType.NULL, List.of(TlsVersion.TLS13), true),
            newTlsCipher(0x0A6A, TlsKeyExchangeType.NULL, TlsAuthType.NULL, Type.NULL, TlsHashType.NULL, List.of(TlsVersion.TLS13), true),
            newTlsCipher(0x0A7A, TlsKeyExchangeType.NULL, TlsAuthType.NULL, Type.NULL, TlsHashType.NULL, List.of(TlsVersion.TLS13), true),
            newTlsCipher(0x0A8A, TlsKeyExchangeType.NULL, TlsAuthType.NULL, Type.NULL, TlsHashType.NULL, List.of(TlsVersion.TLS13), true),
            newTlsCipher(0x0A9A, TlsKeyExchangeType.NULL, TlsAuthType.NULL, Type.NULL, TlsHashType.NULL, List.of(TlsVersion.TLS13), true),
            newTlsCipher(0x0AAA, TlsKeyExchangeType.NULL, TlsAuthType.NULL, Type.NULL, TlsHashType.NULL, List.of(TlsVersion.TLS13), true),
            newTlsCipher(0x0ABA, TlsKeyExchangeType.NULL, TlsAuthType.NULL, Type.NULL, TlsHashType.NULL, List.of(TlsVersion.TLS13), true),
            newTlsCipher(0x0ACA, TlsKeyExchangeType.NULL, TlsAuthType.NULL, Type.NULL, TlsHashType.NULL, List.of(TlsVersion.TLS13), true),
            newTlsCipher(0x0ADA, TlsKeyExchangeType.NULL, TlsAuthType.NULL, Type.NULL, TlsHashType.NULL, List.of(TlsVersion.TLS13), true),
            newTlsCipher(0x0AEA, TlsKeyExchangeType.NULL, TlsAuthType.NULL, Type.NULL, TlsHashType.NULL, List.of(TlsVersion.TLS13), true),
            newTlsCipher(0x0AFA, TlsKeyExchangeType.NULL, TlsAuthType.NULL, Type.NULL, TlsHashType.NULL, List.of(TlsVersion.TLS13), true)
    };
    private static final List<TlsCipher> ALL = List.copyOf(CIPHERS.values());
    private static final List<TlsCipher> RECOMMENDED = CIPHERS.values()
            .stream()
            .filter(TlsCipher::recommended)
            .toList();
    //</editor-fold>

    //<editor-fold desc="Accessors">
    public static TlsCipher aes128Ccm8Sha256() {
        return TLS_AES_128_CCM_8_SHA256;
    }

    public static TlsCipher aes128CcmSha256() {
        return TLS_AES_128_CCM_SHA256;
    }

    public static TlsCipher aes128GcmSha256() {
        return TLS_AES_128_GCM_SHA256;
    }

    public static TlsCipher aes256GcmSha384() {
        return TLS_AES_256_GCM_SHA384;
    }

    public static TlsCipher chacha20Poly1305Sha256() {
        return TLS_CHACHA20_POLY1305_SHA256;
    }

    public static TlsCipher dhAnonExportWithDes40CbcSha() {
        return TLS_DH_ANON_EXPORT_WITH_DES40_CBC_SHA;
    }

    public static TlsCipher dhAnonExportWithRc440Md5() {
        return TLS_DH_ANON_EXPORT_WITH_RC4_40_MD5;
    }

    public static TlsCipher dhAnonWith3desEdeCbcSha() {
        return TLS_DH_ANON_WITH_3DES_EDE_CBC_SHA;
    }

    public static TlsCipher dhAnonWithAes128CbcSha() {
        return TLS_DH_ANON_WITH_AES_128_CBC_SHA;
    }

    public static TlsCipher dhAnonWithAes128CbcSha256() {
        return TLS_DH_ANON_WITH_AES_128_CBC_SHA256;
    }

    public static TlsCipher dhAnonWithAes128GcmSha256() {
        return TLS_DH_ANON_WITH_AES_128_GCM_SHA256;
    }

    public static TlsCipher dhAnonWithAes256CbcSha() {
        return TLS_DH_ANON_WITH_AES_256_CBC_SHA;
    }

    public static TlsCipher dhAnonWithAes256CbcSha256() {
        return TLS_DH_ANON_WITH_AES_256_CBC_SHA256;
    }

    public static TlsCipher dhAnonWithAes256GcmSha384() {
        return TLS_DH_ANON_WITH_AES_256_GCM_SHA384;
    }

    public static TlsCipher dhAnonWithAria128CbcSha256() {
        return TLS_DH_ANON_WITH_ARIA_128_CBC_SHA256;
    }

    public static TlsCipher dhAnonWithAria128GcmSha256() {
        return TLS_DH_ANON_WITH_ARIA_128_GCM_SHA256;
    }

    public static TlsCipher dhAnonWithAria256CbcSha384() {
        return TLS_DH_ANON_WITH_ARIA_256_CBC_SHA384;
    }

    public static TlsCipher dhAnonWithAria256GcmSha384() {
        return TLS_DH_ANON_WITH_ARIA_256_GCM_SHA384;
    }

    public static TlsCipher dhAnonWithCamellia128CbcSha() {
        return TLS_DH_ANON_WITH_CAMELLIA_128_CBC_SHA;
    }

    public static TlsCipher dhAnonWithCamellia128CbcSha256() {
        return TLS_DH_ANON_WITH_CAMELLIA_128_CBC_SHA256;
    }

    public static TlsCipher dhAnonWithCamellia128GcmSha256() {
        return TLS_DH_ANON_WITH_CAMELLIA_128_GCM_SHA256;
    }

    public static TlsCipher dhAnonWithCamellia256CbcSha() {
        return TLS_DH_ANON_WITH_CAMELLIA_256_CBC_SHA;
    }

    public static TlsCipher dhAnonWithCamellia256CbcSha256() {
        return TLS_DH_ANON_WITH_CAMELLIA_256_CBC_SHA256;
    }

    public static TlsCipher dhAnonWithCamellia256GcmSha384() {
        return TLS_DH_ANON_WITH_CAMELLIA_256_GCM_SHA384;
    }

    public static TlsCipher dhAnonWithDesCbcSha() {
        return TLS_DH_ANON_WITH_DES_CBC_SHA;
    }

    public static TlsCipher dhAnonWithRc4128Md5() {
        return TLS_DH_ANON_WITH_RC4_128_MD5;
    }

    public static TlsCipher dhAnonWithSeedCbcSha() {
        return TLS_DH_ANON_WITH_SEED_CBC_SHA;
    }

    public static TlsCipher dhDssExportWithDes40CbcSha() {
        return TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA;
    }

    public static TlsCipher dhDssWith3desEdeCbcSha() {
        return TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA;
    }

    public static TlsCipher dhDssWithAes128CbcSha() {
        return TLS_DH_DSS_WITH_AES_128_CBC_SHA;
    }

    public static TlsCipher dhDssWithAes128CbcSha256() {
        return TLS_DH_DSS_WITH_AES_128_CBC_SHA256;
    }

    public static TlsCipher dhDssWithAes128GcmSha256() {
        return TLS_DH_DSS_WITH_AES_128_GCM_SHA256;
    }

    public static TlsCipher dhDssWithAes256CbcSha() {
        return TLS_DH_DSS_WITH_AES_256_CBC_SHA;
    }

    public static TlsCipher dhDssWithAes256CbcSha256() {
        return TLS_DH_DSS_WITH_AES_256_CBC_SHA256;
    }

    public static TlsCipher dhDssWithAes256GcmSha384() {
        return TLS_DH_DSS_WITH_AES_256_GCM_SHA384;
    }

    public static TlsCipher dhDssWithAria128CbcSha256() {
        return TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256;
    }

    public static TlsCipher dhDssWithAria128GcmSha256() {
        return TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256;
    }

    public static TlsCipher dhDssWithAria256CbcSha384() {
        return TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384;
    }

    public static TlsCipher dhDssWithAria256GcmSha384() {
        return TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384;
    }

    public static TlsCipher dhDssWithCamellia128CbcSha() {
        return TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA;
    }

    public static TlsCipher dhDssWithCamellia128CbcSha256() {
        return TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256;
    }

    public static TlsCipher dhDssWithCamellia128GcmSha256() {
        return TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256;
    }

    public static TlsCipher dhDssWithCamellia256CbcSha() {
        return TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA;
    }

    public static TlsCipher dhDssWithCamellia256CbcSha256() {
        return TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256;
    }

    public static TlsCipher dhDssWithCamellia256GcmSha384() {
        return TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384;
    }

    public static TlsCipher dhDssWithDesCbcSha() {
        return TLS_DH_DSS_WITH_DES_CBC_SHA;
    }

    public static TlsCipher dhDssWithSeedCbcSha() {
        return TLS_DH_DSS_WITH_SEED_CBC_SHA;
    }

    public static TlsCipher dheDssExportWithDes40CbcSha() {
        return TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA;
    }

    public static TlsCipher dheDssWith3desEdeCbcSha() {
        return TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA;
    }

    public static TlsCipher dheDssWithAes128CbcSha() {
        return TLS_DHE_DSS_WITH_AES_128_CBC_SHA;
    }

    public static TlsCipher dheDssWithAes128CbcSha256() {
        return TLS_DHE_DSS_WITH_AES_128_CBC_SHA256;
    }

    public static TlsCipher dheDssWithAes128GcmSha256() {
        return TLS_DHE_DSS_WITH_AES_128_GCM_SHA256;
    }

    public static TlsCipher dheDssWithAes256CbcSha() {
        return TLS_DHE_DSS_WITH_AES_256_CBC_SHA;
    }

    public static TlsCipher dheDssWithAes256CbcSha256() {
        return TLS_DHE_DSS_WITH_AES_256_CBC_SHA256;
    }

    public static TlsCipher dheDssWithAes256GcmSha384() {
        return TLS_DHE_DSS_WITH_AES_256_GCM_SHA384;
    }

    public static TlsCipher dheDssWithAria128CbcSha256() {
        return TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256;
    }

    public static TlsCipher dheDssWithAria128GcmSha256() {
        return TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256;
    }

    public static TlsCipher dheDssWithAria256CbcSha384() {
        return TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384;
    }

    public static TlsCipher dheDssWithAria256GcmSha384() {
        return TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384;
    }

    public static TlsCipher dheDssWithCamellia128CbcSha() {
        return TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA;
    }

    public static TlsCipher dheDssWithCamellia128CbcSha256() {
        return TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256;
    }

    public static TlsCipher dheDssWithCamellia128GcmSha256() {
        return TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256;
    }

    public static TlsCipher dheDssWithCamellia256CbcSha() {
        return TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA;
    }

    public static TlsCipher dheDssWithCamellia256CbcSha256() {
        return TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256;
    }

    public static TlsCipher dheDssWithCamellia256GcmSha384() {
        return TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384;
    }

    public static TlsCipher dheDssWithDesCbcSha() {
        return TLS_DHE_DSS_WITH_DES_CBC_SHA;
    }

    public static TlsCipher dheDssWithSeedCbcSha() {
        return TLS_DHE_DSS_WITH_SEED_CBC_SHA;
    }

    public static TlsCipher dhePskWith3desEdeCbcSha() {
        return TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA;
    }

    public static TlsCipher dhePskWithAes128CbcSha() {
        return TLS_DHE_PSK_WITH_AES_128_CBC_SHA;
    }

    public static TlsCipher dhePskWithAes128CbcSha256() {
        return TLS_DHE_PSK_WITH_AES_128_CBC_SHA256;
    }

    public static TlsCipher dhePskWithAes128Ccm() {
        return TLS_DHE_PSK_WITH_AES_128_CCM;
    }

    public static TlsCipher dhePskWithAes128GcmSha256() {
        return TLS_DHE_PSK_WITH_AES_128_GCM_SHA256;
    }

    public static TlsCipher dhePskWithAes256CbcSha() {
        return TLS_DHE_PSK_WITH_AES_256_CBC_SHA;
    }

    public static TlsCipher dhePskWithAes256CbcSha384() {
        return TLS_DHE_PSK_WITH_AES_256_CBC_SHA384;
    }

    public static TlsCipher dhePskWithAes256Ccm() {
        return TLS_DHE_PSK_WITH_AES_256_CCM;
    }

    public static TlsCipher dhePskWithAes256GcmSha384() {
        return TLS_DHE_PSK_WITH_AES_256_GCM_SHA384;
    }

    public static TlsCipher dhePskWithAria128CbcSha256() {
        return TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256;
    }

    public static TlsCipher dhePskWithAria128GcmSha256() {
        return TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256;
    }

    public static TlsCipher dhePskWithAria256CbcSha384() {
        return TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384;
    }

    public static TlsCipher dhePskWithAria256GcmSha384() {
        return TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384;
    }

    public static TlsCipher dhePskWithCamellia128CbcSha256() {
        return TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256;
    }

    public static TlsCipher dhePskWithCamellia128GcmSha256() {
        return TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256;
    }

    public static TlsCipher dhePskWithCamellia256CbcSha384() {
        return TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384;
    }

    public static TlsCipher dhePskWithCamellia256GcmSha384() {
        return TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384;
    }

    public static TlsCipher dhePskWithChacha20Poly1305Sha256() {
        return TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256;
    }

    public static TlsCipher dhePskWithNullSha() {
        return TLS_DHE_PSK_WITH_NULL_SHA;
    }

    public static TlsCipher dhePskWithNullSha256() {
        return TLS_DHE_PSK_WITH_NULL_SHA256;
    }

    public static TlsCipher dhePskWithNullSha384() {
        return TLS_DHE_PSK_WITH_NULL_SHA384;
    }

    public static TlsCipher dhePskWithRc4128Sha() {
        return TLS_DHE_PSK_WITH_RC4_128_SHA;
    }

    public static TlsCipher dheRsaExportWithDes40CbcSha() {
        return TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA;
    }

    public static TlsCipher dheRsaWith3desEdeCbcSha() {
        return TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA;
    }

    public static TlsCipher dheRsaWithAes128CbcSha() {
        return TLS_DHE_RSA_WITH_AES_128_CBC_SHA;
    }

    public static TlsCipher dheRsaWithAes128CbcSha256() {
        return TLS_DHE_RSA_WITH_AES_128_CBC_SHA256;
    }

    public static TlsCipher dheRsaWithAes128Ccm() {
        return TLS_DHE_RSA_WITH_AES_128_CCM;
    }

    public static TlsCipher dheRsaWithAes128Ccm8() {
        return TLS_DHE_RSA_WITH_AES_128_CCM_8;
    }

    public static TlsCipher dheRsaWithAes128GcmSha256() {
        return TLS_DHE_RSA_WITH_AES_128_GCM_SHA256;
    }

    public static TlsCipher dheRsaWithAes256CbcSha() {
        return TLS_DHE_RSA_WITH_AES_256_CBC_SHA;
    }

    public static TlsCipher dheRsaWithAes256CbcSha256() {
        return TLS_DHE_RSA_WITH_AES_256_CBC_SHA256;
    }

    public static TlsCipher dheRsaWithAes256Ccm() {
        return TLS_DHE_RSA_WITH_AES_256_CCM;
    }

    public static TlsCipher dheRsaWithAes256Ccm8() {
        return TLS_DHE_RSA_WITH_AES_256_CCM_8;
    }

    public static TlsCipher dheRsaWithAes256GcmSha384() {
        return TLS_DHE_RSA_WITH_AES_256_GCM_SHA384;
    }

    public static TlsCipher dheRsaWithAria128CbcSha256() {
        return TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256;
    }

    public static TlsCipher dheRsaWithAria128GcmSha256() {
        return TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256;
    }

    public static TlsCipher dheRsaWithAria256CbcSha384() {
        return TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384;
    }

    public static TlsCipher dheRsaWithAria256GcmSha384() {
        return TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384;
    }

    public static TlsCipher dheRsaWithCamellia128CbcSha() {
        return TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA;
    }

    public static TlsCipher dheRsaWithCamellia128CbcSha256() {
        return TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256;
    }

    public static TlsCipher dheRsaWithCamellia128GcmSha256() {
        return TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256;
    }

    public static TlsCipher dheRsaWithCamellia256CbcSha() {
        return TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA;
    }

    public static TlsCipher dheRsaWithCamellia256CbcSha256() {
        return TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256;
    }

    public static TlsCipher dheRsaWithCamellia256GcmSha384() {
        return TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384;
    }

    public static TlsCipher dheRsaWithChacha20Poly1305Sha256() {
        return TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256;
    }

    public static TlsCipher dheRsaWithDesCbcSha() {
        return TLS_DHE_RSA_WITH_DES_CBC_SHA;
    }

    public static TlsCipher dheRsaWithSeedCbcSha() {
        return TLS_DHE_RSA_WITH_SEED_CBC_SHA;
    }

    public static TlsCipher dhRsaExportWithDes40CbcSha() {
        return TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA;
    }

    public static TlsCipher dhRsaWith3desEdeCbcSha() {
        return TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA;
    }

    public static TlsCipher dhRsaWithAes128CbcSha() {
        return TLS_DH_RSA_WITH_AES_128_CBC_SHA;
    }

    public static TlsCipher dhRsaWithAes128CbcSha256() {
        return TLS_DH_RSA_WITH_AES_128_CBC_SHA256;
    }

    public static TlsCipher dhRsaWithAes128GcmSha256() {
        return TLS_DH_RSA_WITH_AES_128_GCM_SHA256;
    }

    public static TlsCipher dhRsaWithAes256CbcSha() {
        return TLS_DH_RSA_WITH_AES_256_CBC_SHA;
    }

    public static TlsCipher dhRsaWithAes256CbcSha256() {
        return TLS_DH_RSA_WITH_AES_256_CBC_SHA256;
    }

    public static TlsCipher dhRsaWithAes256GcmSha384() {
        return TLS_DH_RSA_WITH_AES_256_GCM_SHA384;
    }

    public static TlsCipher dhRsaWithAria128CbcSha256() {
        return TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256;
    }

    public static TlsCipher dhRsaWithAria128GcmSha256() {
        return TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256;
    }

    public static TlsCipher dhRsaWithAria256CbcSha384() {
        return TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384;
    }

    public static TlsCipher dhRsaWithAria256GcmSha384() {
        return TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384;
    }

    public static TlsCipher dhRsaWithCamellia128CbcSha() {
        return TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA;
    }

    public static TlsCipher dhRsaWithCamellia128CbcSha256() {
        return TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256;
    }

    public static TlsCipher dhRsaWithCamellia128GcmSha256() {
        return TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256;
    }

    public static TlsCipher dhRsaWithCamellia256CbcSha() {
        return TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA;
    }

    public static TlsCipher dhRsaWithCamellia256CbcSha256() {
        return TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256;
    }

    public static TlsCipher dhRsaWithCamellia256GcmSha384() {
        return TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384;
    }

    public static TlsCipher dhRsaWithDesCbcSha() {
        return TLS_DH_RSA_WITH_DES_CBC_SHA;
    }

    public static TlsCipher dhRsaWithSeedCbcSha() {
        return TLS_DH_RSA_WITH_SEED_CBC_SHA;
    }

    public static TlsCipher eccpwdWithAes128CcmSha256() {
        return TLS_ECCPWD_WITH_AES_128_CCM_SHA256;
    }

    public static TlsCipher eccpwdWithAes128GcmSha256() {
        return TLS_ECCPWD_WITH_AES_128_GCM_SHA256;
    }

    public static TlsCipher eccpwdWithAes256CcmSha384() {
        return TLS_ECCPWD_WITH_AES_256_CCM_SHA384;
    }

    public static TlsCipher eccpwdWithAes256GcmSha384() {
        return TLS_ECCPWD_WITH_AES_256_GCM_SHA384;
    }

    public static TlsCipher ecdhAnonWith3desEdeCbcSha() {
        return TLS_ECDH_ANON_WITH_3DES_EDE_CBC_SHA;
    }

    public static TlsCipher ecdhAnonWithAes128CbcSha() {
        return TLS_ECDH_ANON_WITH_AES_128_CBC_SHA;
    }

    public static TlsCipher ecdhAnonWithAes256CbcSha() {
        return TLS_ECDH_ANON_WITH_AES_256_CBC_SHA;
    }

    public static TlsCipher ecdhAnonWithNullSha() {
        return TLS_ECDH_ANON_WITH_NULL_SHA;
    }

    public static TlsCipher ecdhAnonWithRc4128Sha() {
        return TLS_ECDH_ANON_WITH_RC4_128_SHA;
    }

    public static TlsCipher ecdhEcdsaWith3desEdeCbcSha() {
        return TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA;
    }

    public static TlsCipher ecdhEcdsaWithAes128CbcSha() {
        return TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA;
    }

    public static TlsCipher ecdhEcdsaWithAes128CbcSha256() {
        return TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256;
    }

    public static TlsCipher ecdhEcdsaWithAes128GcmSha256() {
        return TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256;
    }

    public static TlsCipher ecdhEcdsaWithAes256CbcSha() {
        return TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA;
    }

    public static TlsCipher ecdhEcdsaWithAes256CbcSha384() {
        return TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384;
    }

    public static TlsCipher ecdhEcdsaWithAes256GcmSha384() {
        return TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384;
    }

    public static TlsCipher ecdhEcdsaWithAria128CbcSha256() {
        return TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256;
    }

    public static TlsCipher ecdhEcdsaWithAria128GcmSha256() {
        return TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256;
    }

    public static TlsCipher ecdhEcdsaWithAria256CbcSha384() {
        return TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384;
    }

    public static TlsCipher ecdhEcdsaWithAria256GcmSha384() {
        return TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384;
    }

    public static TlsCipher ecdhEcdsaWithCamellia128CbcSha256() {
        return TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256;
    }

    public static TlsCipher ecdhEcdsaWithCamellia128GcmSha256() {
        return TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256;
    }

    public static TlsCipher ecdhEcdsaWithCamellia256CbcSha384() {
        return TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384;
    }

    public static TlsCipher ecdhEcdsaWithCamellia256GcmSha384() {
        return TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384;
    }

    public static TlsCipher ecdhEcdsaWithNullSha() {
        return TLS_ECDH_ECDSA_WITH_NULL_SHA;
    }

    public static TlsCipher ecdhEcdsaWithRc4128Sha() {
        return TLS_ECDH_ECDSA_WITH_RC4_128_SHA;
    }

    public static TlsCipher ecdheEcdsaWith3desEdeCbcSha() {
        return TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA;
    }

    public static TlsCipher ecdheEcdsaWithAes128CbcSha() {
        return TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA;
    }

    public static TlsCipher ecdheEcdsaWithAes128CbcSha256() {
        return TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256;
    }

    public static TlsCipher ecdheEcdsaWithAes128Ccm() {
        return TLS_ECDHE_ECDSA_WITH_AES_128_CCM;
    }

    public static TlsCipher ecdheEcdsaWithAes128Ccm8() {
        return TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8;
    }

    public static TlsCipher ecdheEcdsaWithAes128GcmSha256() {
        return TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
    }

    public static TlsCipher ecdheEcdsaWithAes256CbcSha() {
        return TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA;
    }

    public static TlsCipher ecdheEcdsaWithAes256CbcSha384() {
        return TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384;
    }

    public static TlsCipher ecdheEcdsaWithAes256Ccm() {
        return TLS_ECDHE_ECDSA_WITH_AES_256_CCM;
    }

    public static TlsCipher ecdheEcdsaWithAes256Ccm8() {
        return TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8;
    }

    public static TlsCipher ecdheEcdsaWithAes256GcmSha384() {
        return TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384;
    }

    public static TlsCipher ecdheEcdsaWithAria128CbcSha256() {
        return TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256;
    }

    public static TlsCipher ecdheEcdsaWithAria128GcmSha256() {
        return TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256;
    }

    public static TlsCipher ecdheEcdsaWithAria256CbcSha384() {
        return TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384;
    }

    public static TlsCipher ecdheEcdsaWithAria256GcmSha384() {
        return TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384;
    }

    public static TlsCipher ecdheEcdsaWithCamellia128CbcSha256() {
        return TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256;
    }

    public static TlsCipher ecdheEcdsaWithCamellia128GcmSha256() {
        return TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256;
    }

    public static TlsCipher ecdheEcdsaWithCamellia256CbcSha384() {
        return TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384;
    }

    public static TlsCipher ecdheEcdsaWithCamellia256GcmSha384() {
        return TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384;
    }

    public static TlsCipher ecdheEcdsaWithChacha20Poly1305Sha256() {
        return TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256;
    }

    public static TlsCipher ecdheEcdsaWithNullSha() {
        return TLS_ECDHE_ECDSA_WITH_NULL_SHA;
    }

    public static TlsCipher ecdheEcdsaWithRc4128Sha() {
        return TLS_ECDHE_ECDSA_WITH_RC4_128_SHA;
    }

    public static TlsCipher ecdhePskWith3desEdeCbcSha() {
        return TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA;
    }

    public static TlsCipher ecdhePskWithAes128CbcSha() {
        return TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA;
    }

    public static TlsCipher ecdhePskWithAes128CbcSha256() {
        return TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256;
    }

    public static TlsCipher ecdhePskWithAes128Ccm8Sha256() {
        return TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256;
    }

    public static TlsCipher ecdhePskWithAes128CcmSha256() {
        return TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256;
    }

    public static TlsCipher ecdhePskWithAes128GcmSha256() {
        return TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256;
    }

    public static TlsCipher ecdhePskWithAes256CbcSha() {
        return TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA;
    }

    public static TlsCipher ecdhePskWithAes256CbcSha384() {
        return TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384;
    }

    public static TlsCipher ecdhePskWithAes256GcmSha384() {
        return TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384;
    }

    public static TlsCipher ecdhePskWithAria128CbcSha256() {
        return TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256;
    }

    public static TlsCipher ecdhePskWithAria256CbcSha384() {
        return TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384;
    }

    public static TlsCipher ecdhePskWithCamellia128CbcSha256() {
        return TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256;
    }

    public static TlsCipher ecdhePskWithCamellia256CbcSha384() {
        return TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384;
    }

    public static TlsCipher ecdhePskWithChacha20Poly1305Sha256() {
        return TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256;
    }

    public static TlsCipher ecdhePskWithNullSha() {
        return TLS_ECDHE_PSK_WITH_NULL_SHA;
    }

    public static TlsCipher ecdhePskWithNullSha256() {
        return TLS_ECDHE_PSK_WITH_NULL_SHA256;
    }

    public static TlsCipher ecdhePskWithNullSha384() {
        return TLS_ECDHE_PSK_WITH_NULL_SHA384;
    }

    public static TlsCipher ecdhePskWithRc4128Sha() {
        return TLS_ECDHE_PSK_WITH_RC4_128_SHA;
    }

    public static TlsCipher ecdheRsaWith3desEdeCbcSha() {
        return TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA;
    }

    public static TlsCipher ecdheRsaWithAes128CbcSha() {
        return TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA;
    }

    public static TlsCipher ecdheRsaWithAes128CbcSha256() {
        return TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256;
    }

    public static TlsCipher ecdheRsaWithAes128GcmSha256() {
        return TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256;
    }

    public static TlsCipher ecdheRsaWithAes256CbcSha() {
        return TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA;
    }

    public static TlsCipher ecdheRsaWithAes256CbcSha384() {
        return TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384;
    }

    public static TlsCipher ecdheRsaWithAes256GcmSha384() {
        return TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384;
    }

    public static TlsCipher ecdheRsaWithAria128CbcSha256() {
        return TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256;
    }

    public static TlsCipher ecdheRsaWithAria128GcmSha256() {
        return TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256;
    }

    public static TlsCipher ecdheRsaWithAria256CbcSha384() {
        return TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384;
    }

    public static TlsCipher ecdheRsaWithAria256GcmSha384() {
        return TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384;
    }

    public static TlsCipher ecdheRsaWithCamellia128CbcSha256() {
        return TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256;
    }

    public static TlsCipher ecdheRsaWithCamellia128GcmSha256() {
        return TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256;
    }

    public static TlsCipher ecdheRsaWithCamellia256CbcSha384() {
        return TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384;
    }

    public static TlsCipher ecdheRsaWithCamellia256GcmSha384() {
        return TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384;
    }

    public static TlsCipher ecdheRsaWithChacha20Poly1305Sha256() {
        return TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256;
    }

    public static TlsCipher ecdheRsaWithNullSha() {
        return TLS_ECDHE_RSA_WITH_NULL_SHA;
    }

    public static TlsCipher ecdheRsaWithRc4128Sha() {
        return TLS_ECDHE_RSA_WITH_RC4_128_SHA;
    }

    public static TlsCipher ecdhRsaWith3desEdeCbcSha() {
        return TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA;
    }

    public static TlsCipher ecdhRsaWithAes128CbcSha() {
        return TLS_ECDH_RSA_WITH_AES_128_CBC_SHA;
    }

    public static TlsCipher ecdhRsaWithAes128CbcSha256() {
        return TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256;
    }

    public static TlsCipher ecdhRsaWithAes128GcmSha256() {
        return TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256;
    }

    public static TlsCipher ecdhRsaWithAes256CbcSha() {
        return TLS_ECDH_RSA_WITH_AES_256_CBC_SHA;
    }

    public static TlsCipher ecdhRsaWithAes256CbcSha384() {
        return TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384;
    }

    public static TlsCipher ecdhRsaWithAes256GcmSha384() {
        return TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384;
    }

    public static TlsCipher ecdhRsaWithAria128CbcSha256() {
        return TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256;
    }

    public static TlsCipher ecdhRsaWithAria128GcmSha256() {
        return TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256;
    }

    public static TlsCipher ecdhRsaWithAria256CbcSha384() {
        return TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384;
    }

    public static TlsCipher ecdhRsaWithAria256GcmSha384() {
        return TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384;
    }

    public static TlsCipher ecdhRsaWithCamellia128CbcSha256() {
        return TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256;
    }

    public static TlsCipher ecdhRsaWithCamellia128GcmSha256() {
        return TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256;
    }

    public static TlsCipher ecdhRsaWithCamellia256CbcSha384() {
        return TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384;
    }

    public static TlsCipher ecdhRsaWithCamellia256GcmSha384() {
        return TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384;
    }

    public static TlsCipher ecdhRsaWithNullSha() {
        return TLS_ECDH_RSA_WITH_NULL_SHA;
    }

    public static TlsCipher ecdhRsaWithRc4128Sha() {
        return TLS_ECDH_RSA_WITH_RC4_128_SHA;
    }

    public static TlsCipher gostr341112256With28147CntImit() {
        return TLS_GOSTR341112_256_WITH_28147_CNT_IMIT;
    }

    public static TlsCipher gostr341112256WithKuznyechikCtrOmac() {
        return TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC;
    }

    public static TlsCipher gostr341112256WithKuznyechikMgmL() {
        return TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L;
    }

    public static TlsCipher gostr341112256WithKuznyechikMgmS() {
        return TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S;
    }

    public static TlsCipher gostr341112256WithMagmaCtrOmac() {
        return TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC;
    }

    public static TlsCipher gostr341112256WithMagmaMgmL() {
        return TLS_GOSTR341112_256_WITH_MAGMA_MGM_L;
    }

    public static TlsCipher gostr341112256WithMagmaMgmS() {
        return TLS_GOSTR341112_256_WITH_MAGMA_MGM_S;
    }

    public static TlsCipher krb5ExportWithDesCbc40Md5() {
        return TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5;
    }

    public static TlsCipher krb5ExportWithDesCbc40Sha() {
        return TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA;
    }

    public static TlsCipher krb5ExportWithRc2Cbc40Md5() {
        return TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5;
    }

    public static TlsCipher krb5ExportWithRc2Cbc40Sha() {
        return TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA;
    }

    public static TlsCipher krb5ExportWithRc440Md5() {
        return TLS_KRB5_EXPORT_WITH_RC4_40_MD5;
    }

    public static TlsCipher krb5ExportWithRc440Sha() {
        return TLS_KRB5_EXPORT_WITH_RC4_40_SHA;
    }

    public static TlsCipher krb5With3desEdeCbcMd5() {
        return TLS_KRB5_WITH_3DES_EDE_CBC_MD5;
    }

    public static TlsCipher krb5With3desEdeCbcSha() {
        return TLS_KRB5_WITH_3DES_EDE_CBC_SHA;
    }

    public static TlsCipher krb5WithDesCbcMd5() {
        return TLS_KRB5_WITH_DES_CBC_MD5;
    }

    public static TlsCipher krb5WithDesCbcSha() {
        return TLS_KRB5_WITH_DES_CBC_SHA;
    }

    public static TlsCipher krb5WithIdeaCbcMd5() {
        return TLS_KRB5_WITH_IDEA_CBC_MD5;
    }

    public static TlsCipher krb5WithIdeaCbcSha() {
        return TLS_KRB5_WITH_IDEA_CBC_SHA;
    }

    public static TlsCipher krb5WithRc4128Md5() {
        return TLS_KRB5_WITH_RC4_128_MD5;
    }

    public static TlsCipher krb5WithRc4128Sha() {
        return TLS_KRB5_WITH_RC4_128_SHA;
    }

    public static TlsCipher nullWithNullNull() {
        return TLS_NULL_WITH_NULL_NULL;
    }

    public static TlsCipher pskDheWithAes128Ccm8() {
        return TLS_PSK_DHE_WITH_AES_128_CCM_8;
    }

    public static TlsCipher pskDheWithAes256Ccm8() {
        return TLS_PSK_DHE_WITH_AES_256_CCM_8;
    }

    public static TlsCipher pskWith3desEdeCbcSha() {
        return TLS_PSK_WITH_3DES_EDE_CBC_SHA;
    }

    public static TlsCipher pskWithAes128CbcSha() {
        return TLS_PSK_WITH_AES_128_CBC_SHA;
    }

    public static TlsCipher pskWithAes128CbcSha256() {
        return TLS_PSK_WITH_AES_128_CBC_SHA256;
    }

    public static TlsCipher pskWithAes128Ccm() {
        return TLS_PSK_WITH_AES_128_CCM;
    }

    public static TlsCipher pskWithAes128Ccm8() {
        return TLS_PSK_WITH_AES_128_CCM_8;
    }

    public static TlsCipher pskWithAes128GcmSha256() {
        return TLS_PSK_WITH_AES_128_GCM_SHA256;
    }

    public static TlsCipher pskWithAes256CbcSha() {
        return TLS_PSK_WITH_AES_256_CBC_SHA;
    }

    public static TlsCipher pskWithAes256CbcSha384() {
        return TLS_PSK_WITH_AES_256_CBC_SHA384;
    }

    public static TlsCipher pskWithAes256Ccm() {
        return TLS_PSK_WITH_AES_256_CCM;
    }

    public static TlsCipher pskWithAes256Ccm8() {
        return TLS_PSK_WITH_AES_256_CCM_8;
    }

    public static TlsCipher pskWithAes256GcmSha384() {
        return TLS_PSK_WITH_AES_256_GCM_SHA384;
    }

    public static TlsCipher pskWithAria128CbcSha256() {
        return TLS_PSK_WITH_ARIA_128_CBC_SHA256;
    }

    public static TlsCipher pskWithAria128GcmSha256() {
        return TLS_PSK_WITH_ARIA_128_GCM_SHA256;
    }

    public static TlsCipher pskWithAria256CbcSha384() {
        return TLS_PSK_WITH_ARIA_256_CBC_SHA384;
    }

    public static TlsCipher pskWithAria256GcmSha384() {
        return TLS_PSK_WITH_ARIA_256_GCM_SHA384;
    }

    public static TlsCipher pskWithCamellia128CbcSha256() {
        return TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256;
    }

    public static TlsCipher pskWithCamellia128GcmSha256() {
        return TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256;
    }

    public static TlsCipher pskWithCamellia256CbcSha384() {
        return TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384;
    }

    public static TlsCipher pskWithCamellia256GcmSha384() {
        return TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384;
    }

    public static TlsCipher pskWithChacha20Poly1305Sha256() {
        return TLS_PSK_WITH_CHACHA20_POLY1305_SHA256;
    }

    public static TlsCipher pskWithNullSha() {
        return TLS_PSK_WITH_NULL_SHA;
    }

    public static TlsCipher pskWithNullSha256() {
        return TLS_PSK_WITH_NULL_SHA256;
    }

    public static TlsCipher pskWithNullSha384() {
        return TLS_PSK_WITH_NULL_SHA384;
    }

    public static TlsCipher pskWithRc4128Sha() {
        return TLS_PSK_WITH_RC4_128_SHA;
    }

    public static TlsCipher rsaExportWithDes40CbcSha() {
        return TLS_RSA_EXPORT_WITH_DES40_CBC_SHA;
    }

    public static TlsCipher rsaExportWithRc2Cbc40Md5() {
        return TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5;
    }

    public static TlsCipher rsaExportWithRc440Md5() {
        return TLS_RSA_EXPORT_WITH_RC4_40_MD5;
    }

    public static TlsCipher rsaPskWith3desEdeCbcSha() {
        return TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA;
    }

    public static TlsCipher rsaPskWithAes128CbcSha() {
        return TLS_RSA_PSK_WITH_AES_128_CBC_SHA;
    }

    public static TlsCipher rsaPskWithAes128CbcSha256() {
        return TLS_RSA_PSK_WITH_AES_128_CBC_SHA256;
    }

    public static TlsCipher rsaPskWithAes128GcmSha256() {
        return TLS_RSA_PSK_WITH_AES_128_GCM_SHA256;
    }

    public static TlsCipher rsaPskWithAes256CbcSha() {
        return TLS_RSA_PSK_WITH_AES_256_CBC_SHA;
    }

    public static TlsCipher rsaPskWithAes256CbcSha384() {
        return TLS_RSA_PSK_WITH_AES_256_CBC_SHA384;
    }

    public static TlsCipher rsaPskWithAes256GcmSha384() {
        return TLS_RSA_PSK_WITH_AES_256_GCM_SHA384;
    }

    public static TlsCipher rsaPskWithAria128CbcSha256() {
        return TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256;
    }

    public static TlsCipher rsaPskWithAria128GcmSha256() {
        return TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256;
    }

    public static TlsCipher rsaPskWithAria256CbcSha384() {
        return TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384;
    }

    public static TlsCipher rsaPskWithAria256GcmSha384() {
        return TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384;
    }

    public static TlsCipher rsaPskWithCamellia128CbcSha256() {
        return TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256;
    }

    public static TlsCipher rsaPskWithCamellia128GcmSha256() {
        return TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256;
    }

    public static TlsCipher rsaPskWithCamellia256CbcSha384() {
        return TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384;
    }

    public static TlsCipher rsaPskWithCamellia256GcmSha384() {
        return TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384;
    }

    public static TlsCipher rsaPskWithChacha20Poly1305Sha256() {
        return TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256;
    }

    public static TlsCipher rsaPskWithNullSha() {
        return TLS_RSA_PSK_WITH_NULL_SHA;
    }

    public static TlsCipher rsaPskWithNullSha256() {
        return TLS_RSA_PSK_WITH_NULL_SHA256;
    }

    public static TlsCipher rsaPskWithNullSha384() {
        return TLS_RSA_PSK_WITH_NULL_SHA384;
    }

    public static TlsCipher rsaPskWithRc4128Sha() {
        return TLS_RSA_PSK_WITH_RC4_128_SHA;
    }

    public static TlsCipher rsaWith3desEdeCbcSha() {
        return TLS_RSA_WITH_3DES_EDE_CBC_SHA;
    }

    public static TlsCipher rsaWithAes128CbcSha() {
        return TLS_RSA_WITH_AES_128_CBC_SHA;
    }

    public static TlsCipher rsaWithAes128CbcSha256() {
        return TLS_RSA_WITH_AES_128_CBC_SHA256;
    }

    public static TlsCipher rsaWithAes128Ccm() {
        return TLS_RSA_WITH_AES_128_CCM;
    }

    public static TlsCipher rsaWithAes128Ccm8() {
        return TLS_RSA_WITH_AES_128_CCM_8;
    }

    public static TlsCipher rsaWithAes128GcmSha256() {
        return TLS_RSA_WITH_AES_128_GCM_SHA256;
    }

    public static TlsCipher rsaWithAes256CbcSha() {
        return TLS_RSA_WITH_AES_256_CBC_SHA;
    }

    public static TlsCipher rsaWithAes256CbcSha256() {
        return TLS_RSA_WITH_AES_256_CBC_SHA256;
    }

    public static TlsCipher rsaWithAes256Ccm() {
        return TLS_RSA_WITH_AES_256_CCM;
    }

    public static TlsCipher rsaWithAes256Ccm8() {
        return TLS_RSA_WITH_AES_256_CCM_8;
    }

    public static TlsCipher rsaWithAes256GcmSha384() {
        return TLS_RSA_WITH_AES_256_GCM_SHA384;
    }

    public static TlsCipher rsaWithAria128CbcSha256() {
        return TLS_RSA_WITH_ARIA_128_CBC_SHA256;
    }

    public static TlsCipher rsaWithAria128GcmSha256() {
        return TLS_RSA_WITH_ARIA_128_GCM_SHA256;
    }

    public static TlsCipher rsaWithAria256CbcSha384() {
        return TLS_RSA_WITH_ARIA_256_CBC_SHA384;
    }

    public static TlsCipher rsaWithAria256GcmSha384() {
        return TLS_RSA_WITH_ARIA_256_GCM_SHA384;
    }

    public static TlsCipher rsaWithCamellia128CbcSha() {
        return TLS_RSA_WITH_CAMELLIA_128_CBC_SHA;
    }

    public static TlsCipher rsaWithCamellia128CbcSha256() {
        return TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256;
    }

    public static TlsCipher rsaWithCamellia128GcmSha256() {
        return TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256;
    }

    public static TlsCipher rsaWithCamellia256CbcSha() {
        return TLS_RSA_WITH_CAMELLIA_256_CBC_SHA;
    }

    public static TlsCipher rsaWithCamellia256CbcSha256() {
        return TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256;
    }

    public static TlsCipher rsaWithCamellia256GcmSha384() {
        return TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384;
    }

    public static TlsCipher rsaWithDesCbcSha() {
        return TLS_RSA_WITH_DES_CBC_SHA;
    }

    public static TlsCipher rsaWithIdeaCbcSha() {
        return TLS_RSA_WITH_IDEA_CBC_SHA;
    }

    public static TlsCipher rsaWithNullMd5() {
        return TLS_RSA_WITH_NULL_MD5;
    }

    public static TlsCipher rsaWithNullSha() {
        return TLS_RSA_WITH_NULL_SHA;
    }

    public static TlsCipher rsaWithNullSha256() {
        return TLS_RSA_WITH_NULL_SHA256;
    }

    public static TlsCipher rsaWithRc4128Md5() {
        return TLS_RSA_WITH_RC4_128_MD5;
    }

    public static TlsCipher rsaWithRc4128Sha() {
        return TLS_RSA_WITH_RC4_128_SHA;
    }

    public static TlsCipher rsaWithSeedCbcSha() {
        return TLS_RSA_WITH_SEED_CBC_SHA;
    }

    public static TlsCipher sha256Sha256() {
        return TLS_SHA256_SHA256;
    }

    public static TlsCipher sha384Sha384() {
        return TLS_SHA384_SHA384;
    }

    public static TlsCipher sm4CcmSm3() {
        return TLS_SM4_CCM_SM3;
    }

    public static TlsCipher sm4GcmSm3() {
        return TLS_SM4_GCM_SM3;
    }

    public static TlsCipher srpShaDssWith3desEdeCbcSha() {
        return TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA;
    }

    public static TlsCipher srpShaDssWithAes128CbcSha() {
        return TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA;
    }

    public static TlsCipher srpShaDssWithAes256CbcSha() {
        return TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA;
    }

    public static TlsCipher srpShaRsaWith3desEdeCbcSha() {
        return TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA;
    }

    public static TlsCipher srpShaRsaWithAes128CbcSha() {
        return TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA;
    }

    public static TlsCipher srpShaRsaWithAes256CbcSha() {
        return TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA;
    }

    public static TlsCipher srpShaWith3desEdeCbcSha() {
        return TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA;
    }

    public static TlsCipher srpShaWithAes128CbcSha() {
        return TLS_SRP_SHA_WITH_AES_128_CBC_SHA;
    }

    public static TlsCipher srpShaWithAes256CbcSha() {
        return TLS_SRP_SHA_WITH_AES_256_CBC_SHA;
    }

    public static TlsCipher grease0A() {
        return TLS_GREASE[0];
    }

    public static TlsCipher grease1A() {
        return TLS_GREASE[1];
    }

    public static TlsCipher grease2A() {
        return TLS_GREASE[2];
    }

    public static TlsCipher grease3A() {
        return TLS_GREASE[3];
    }

    public static TlsCipher grease4A() {
        return TLS_GREASE[4];
    }

    public static TlsCipher grease5A() {
        return TLS_GREASE[5];
    }

    public static TlsCipher grease6A() {
        return TLS_GREASE[6];
    }

    public static TlsCipher grease7A() {
        return TLS_GREASE[7];
    }

    public static TlsCipher grease8A() {
        return TLS_GREASE[8];
    }

    public static TlsCipher grease9A() {
        return TLS_GREASE[9];
    }

    public static TlsCipher greaseAA() {
        return TLS_GREASE[10];
    }

    public static TlsCipher greaseBA() {
        return TLS_GREASE[11];
    }

    public static TlsCipher greaseCA() {
        return TLS_GREASE[12];
    }

    public static TlsCipher greaseDA() {
        return TLS_GREASE[13];
    }

    public static TlsCipher greaseEA() {
        return TLS_GREASE[14];
    }

    public static TlsCipher greaseFA() {
        return TLS_GREASE[15];
    }

    public static TlsCipher grease(int index) {
        if (index < 0 || index >= TLS_GREASE.length) {
            throw new IndexOutOfBoundsException("Index %s is not within bounds [0, 16)".formatted(index));
        }

        return TLS_GREASE[index];
    }

    public static TlsCipher grease() {
        var random = new SecureRandom();
        return TLS_GREASE[random.nextInt(0, TLS_GREASE.length)];
    }

    public static List<TlsCipher> allCiphers() {
        return ALL;
    }

    public static List<TlsCipher> recommendedCiphers() {
        return RECOMMENDED;
    }
    //</editor-fold>

    private final int id;
    private final TlsKeyExchangeType keyExchange;
    private final TlsAuthType auth;
    private final Type type;
    private final TlsHashType hashType;
    private final List<TlsVersion> versions;
    private final boolean recommended;
    private TlsCipher(int id, TlsKeyExchangeType keyExchange, TlsAuthType auth, Type type, TlsHashType hashType, List<TlsVersion> versions, boolean recommended) {
        this.id = id;
        this.keyExchange = keyExchange;
        this.auth = auth;
        this.type = type;
        this.hashType = hashType;
        this.versions = versions;
        this.recommended = recommended;
    }

    public int id() {
        return id;
    }

    public TlsKeyExchangeType keyExchange() {
        return keyExchange;
    }

    public TlsAuthType auth() {
        return auth;
    }

    public Type encryption() {
        return type;
    }

    public TlsHashType hash() {
        return hashType;
    }

    public TlsHmacType hmac() {
        return type.mode().category() == Type.Mode.Category.AEAD ? TlsHmacType.NULL : hashType.toHmac();
    }

    public List<TlsVersion> versions() {
        return versions;
    }
    
    public boolean recommended() {
        return recommended;
    }

    @Override
    public boolean equals(Object obj) {
        return obj == this || obj instanceof TlsCipher that && this.id == that.id;
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }

    @Override
    public String toString() {
        return "TlsCipher[" +
                "id=" + id + ", " +
                "keyExchange=" + keyExchange + ", " +
                "auth=" + auth + ", " +
                "cipher=" + type + ", " +
                "hash=" + hashType + ", " +
                "versions=" + versions + ']';
    }

    public enum Type {
        NULL(0, 0, 0, 0, null, Mode.NULL),
        AES_128_CBC(16, 0, 16, 0, null, Mode.CBC),
        AES_128_CCM(16, 0, 12, 4, null, Mode.CCM),
        AES_128_CCM_8(16, 0, 12, 4, null, Mode.CCM_8),
        AES_128_GCM(16, 16, 12, 4, null, Mode.GCM),
        AES_256_CBC(32, 0, 16, 0, null, Mode.CBC),
        AES_256_CCM(32, 0, 12, 4, null, Mode.CCM),
        AES_256_CCM_8(32, 0, 12, 4, null, Mode.CCM_8),
        AES_256_GCM(32, 16, 12, 4, null, Mode.GCM),
        ARIA_128_CBC(16, 0, 16, 0, null, Mode.CBC),
        ARIA_128_GCM(16, 16, 12, 4, null, Mode.GCM),
        ARIA_256_CBC(32, 0, 16, 0, null, Mode.CBC),
        ARIA_256_GCM(32, 16, 12, 4, null, Mode.GCM),
        CAMELLIA_128_CBC(16, 0, 16, 0, null, Mode.CBC),
        CAMELLIA_128_GCM(16, 16, 12, 4, null, Mode.GCM),
        CAMELLIA_256_CBC(32, 0, 16, 0, null, Mode.CBC),
        CAMELLIA_256_GCM(32, 16, 12, 4, null, Mode.GCM),
        CHACHA20_POLY1305(32, 0, 12, 12, null, Mode.INTRINSIC), // Technically this is a AEAD cipher, not a stream cipher FIXME
        DES40_CBC(5, 0, 8, 0, 7, Mode.CBC),
        DES_CBC(7, 0, 8, 0, null, Mode.CBC),
        DES_CBC_40(5, 0, 8, 0, 7, Mode.CBC_40),
        IDEA_CBC(16, 0, 8, 0, null, Mode.CBC),
        KUZNYECHIK_CTR(32, 0, 16, 4, null, Mode.INTRINSIC),
        KUZNYECHIK_MGM_L(32, 0, 12, 4, null, Mode.MGM_L),
        KUZNYECHIK_MGM_S(32, 0, 12, 4, null, Mode.MGM_S),
        MAGMA_CTR(32, 0, 8, 4, null, Mode.INTRINSIC),
        MAGMA_MGM_L(32, 0, 12, 4, null, Mode.MGM_L),
        MAGMA_MGM_S(32, 0, 12, 4, null, Mode.MGM_S),
        RC2_CBC_40(5, 0, 8, 0, 16, Mode.CBC_40),
        RC4_128(16, 0, 0, 0, null, Mode.INTRINSIC),
        RC4_40(5, 0, 0, 0, 16, Mode.INTRINSIC),
        SEED_CBC(16, 0, 16, 0, null, Mode.CBC),
        SM4_CCM(16, 0, 12, 4, null, Mode.CCM),
        SM4_GCM(16, 16, 12, 4, null, Mode.GCM),
        GOST_28147_CNT(32, 0, 8, 4, null, Mode.INTRINSIC),
        TRIPLE_DES_EDE_CBC(21, 0, 8, 0, null, Mode.CBC);

        private final int cipherKeyLength;
        private final int tagLength;
        private final int ivLength;
        private final Integer expandedKeyLength;
        private final int fixedIvLength;
        private final Mode mode;

        Type(int cipherKeyLength, int tagLength, int ivLength, int fixedIvLength, Integer expandedKeyLength, Mode mode) {
            this.cipherKeyLength = cipherKeyLength;
            this.tagLength = tagLength;
            this.ivLength = ivLength;
            this.expandedKeyLength = expandedKeyLength;
            this.fixedIvLength = fixedIvLength;
            this.mode = mode;
        }

        public int tagLength() {
            return tagLength;
        }

        public int cipherKeyLength() {
            return cipherKeyLength;
        }

        public int ivLength() {
            return ivLength;
        }

        public OptionalInt expandedKeyLength() {
            return expandedKeyLength == null ? OptionalInt.empty() : OptionalInt.of(expandedKeyLength);
        }

        public int fixedIvLength() {
            return fixedIvLength;
        }

        public Mode mode() {
            return mode;
        }

        public enum Family {
            AES,
            ARIA,
            CAMELLIA,
            DES,
            DES40,
            IDEA,
            KUZNYECHIK,
            MAGMA,
            RC2,
            RC4,
            SEED,
            SM4,
            GOST_28147,
            TRIPLE_DES_EDE
        }

        public enum Mode {
            NULL(Category.NULL),
            INTRINSIC(Category.STREAM), // For stream ciphers and "special" ciphers like NULL and CHACHA20_POLY1305
            GCM(Category.AEAD),
            CBC(Category.BLOCK),
            CBC_40(Category.BLOCK),
            CCM(Category.AEAD), // (_16)
            CCM_8(Category.AEAD),
            MGM_L(Category.AEAD),
            MGM_S(Category.AEAD);

            private final Category category;

            Mode(Category category) {
                this.category = category;
            }

            public Category category() {
                return category;
            }

            public enum Category {
                NULL,
                STREAM,
                BLOCK,
                AEAD
            }
        }
    }
}