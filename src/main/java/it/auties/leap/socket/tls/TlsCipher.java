package it.auties.leap.socket.tls;

import java.util.List;

public record TlsCipher(
        int id,
        KeyExchange keyExchange,
        Auth auth,
        Encryption encryption,
        Hash hash,
        List<TlsVersion> versions
) {
    //<editor-fold desc="Ciphers">
    private static final TlsCipher TLS_AES_128_CCM_8_SHA256 = new TlsCipher(0x1305, KeyExchange.NULL, Auth.NULL, Encryption.AES_128_CCM_8, Hash.SHA256, List.of(TlsVersion.TLS13));
    private static final TlsCipher TLS_AES_128_CCM_SHA256 = new TlsCipher(0x1304, KeyExchange.NULL, Auth.NULL, Encryption.AES_128_CCM, Hash.SHA256, List.of(TlsVersion.TLS13));
    private static final TlsCipher TLS_AES_128_GCM_SHA256 = new TlsCipher(0x1301, KeyExchange.NULL, Auth.NULL, Encryption.AES_128_GCM, Hash.SHA256, List.of(TlsVersion.TLS13));
    private static final TlsCipher TLS_AES_256_GCM_SHA384 = new TlsCipher(0x1302, KeyExchange.NULL, Auth.NULL, Encryption.AES_256_GCM, Hash.SHA384, List.of(TlsVersion.TLS13));
    private static final TlsCipher TLS_CHACHA20_POLY1305_SHA256 = new TlsCipher(0x1303, KeyExchange.NULL, Auth.NULL, Encryption.CHACHA20_POLY1305, Hash.SHA256, List.of(TlsVersion.TLS13));
    private static final TlsCipher TLS_DH_ANON_EXPORT_WITH_DES40_CBC_SHA = new TlsCipher(0x0019, KeyExchange.DH, Auth.ANON, Encryption.DES40_CBC, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DH_ANON_EXPORT_WITH_RC4_40_MD5 = new TlsCipher(0x0017, KeyExchange.DH, Auth.ANON, Encryption.RC4_40, Hash.MD5, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DH_ANON_WITH_3DES_EDE_CBC_SHA = new TlsCipher(0x001B, KeyExchange.DH, Auth.ANON, Encryption._3DES_EDE_CBC, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DH_ANON_WITH_AES_128_CBC_SHA = new TlsCipher(0x0034, KeyExchange.DH, Auth.ANON, Encryption.AES_128_CBC, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DH_ANON_WITH_AES_128_CBC_SHA256 = new TlsCipher(0x006C, KeyExchange.DH, Auth.ANON, Encryption.AES_128_CBC, Hash.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DH_ANON_WITH_AES_128_GCM_SHA256 = new TlsCipher(0x00A6, KeyExchange.DH, Auth.ANON, Encryption.AES_128_GCM, Hash.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DH_ANON_WITH_AES_256_CBC_SHA = new TlsCipher(0x003A, KeyExchange.DH, Auth.ANON, Encryption.AES_256_CBC, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DH_ANON_WITH_AES_256_CBC_SHA256 = new TlsCipher(0x006D, KeyExchange.DH, Auth.ANON, Encryption.AES_256_CBC, Hash.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DH_ANON_WITH_AES_256_GCM_SHA384 = new TlsCipher(0x00A7, KeyExchange.DH, Auth.ANON, Encryption.AES_256_GCM, Hash.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DH_ANON_WITH_ARIA_128_CBC_SHA256 = new TlsCipher(0xC046, KeyExchange.DH, Auth.ANON, Encryption.ARIA_128_CBC, Hash.SHA256, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DH_ANON_WITH_ARIA_128_GCM_SHA256 = new TlsCipher(0xC05A, KeyExchange.DH, Auth.ANON, Encryption.ARIA_128_GCM, Hash.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DH_ANON_WITH_ARIA_256_CBC_SHA384 = new TlsCipher(0xC047, KeyExchange.DH, Auth.ANON, Encryption.ARIA_256_CBC, Hash.SHA384, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DH_ANON_WITH_ARIA_256_GCM_SHA384 = new TlsCipher(0xC05B, KeyExchange.DH, Auth.ANON, Encryption.ARIA_256_GCM, Hash.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DH_ANON_WITH_CAMELLIA_128_CBC_SHA = new TlsCipher(0x0046, KeyExchange.DH, Auth.ANON, Encryption.CAMELLIA_128_CBC, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DH_ANON_WITH_CAMELLIA_128_CBC_SHA256 = new TlsCipher(0x00BF, KeyExchange.DH, Auth.ANON, Encryption.CAMELLIA_128_CBC, Hash.SHA256, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DH_ANON_WITH_CAMELLIA_128_GCM_SHA256 = new TlsCipher(0xC084, KeyExchange.DH, Auth.ANON, Encryption.CAMELLIA_128_GCM, Hash.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DH_ANON_WITH_CAMELLIA_256_CBC_SHA = new TlsCipher(0x0089, KeyExchange.DH, Auth.ANON, Encryption.CAMELLIA_256_CBC, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DH_ANON_WITH_CAMELLIA_256_CBC_SHA256 = new TlsCipher(0x00C5, KeyExchange.DH, Auth.ANON, Encryption.CAMELLIA_256_CBC, Hash.SHA256, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DH_ANON_WITH_CAMELLIA_256_GCM_SHA384 = new TlsCipher(0xC085, KeyExchange.DH, Auth.ANON, Encryption.CAMELLIA_256_GCM, Hash.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DH_ANON_WITH_DES_CBC_SHA = new TlsCipher(0x001A, KeyExchange.DH, Auth.ANON, Encryption.DES_CBC, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DH_ANON_WITH_RC4_128_MD5 = new TlsCipher(0x0018, KeyExchange.DH, Auth.ANON, Encryption.RC4_128, Hash.MD5, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DH_ANON_WITH_SEED_CBC_SHA = new TlsCipher(0x009B, KeyExchange.DH, Auth.ANON, Encryption.SEED_CBC, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA = new TlsCipher(0x000B, KeyExchange.DH, Auth.DSS, Encryption.DES40_CBC, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA = new TlsCipher(0x000D, KeyExchange.DH, Auth.DSS, Encryption._3DES_EDE_CBC, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DH_DSS_WITH_AES_128_CBC_SHA = new TlsCipher(0x0030, KeyExchange.DH, Auth.DSS, Encryption.AES_128_CBC, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DH_DSS_WITH_AES_128_CBC_SHA256 = new TlsCipher(0x003E, KeyExchange.DH, Auth.DSS, Encryption.AES_128_CBC, Hash.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DH_DSS_WITH_AES_128_GCM_SHA256 = new TlsCipher(0x00A4, KeyExchange.DH, Auth.DSS, Encryption.AES_128_GCM, Hash.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DH_DSS_WITH_AES_256_CBC_SHA = new TlsCipher(0x0036, KeyExchange.DH, Auth.DSS, Encryption.AES_256_CBC, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DH_DSS_WITH_AES_256_CBC_SHA256 = new TlsCipher(0x0068, KeyExchange.DH, Auth.DSS, Encryption.AES_256_CBC, Hash.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DH_DSS_WITH_AES_256_GCM_SHA384 = new TlsCipher(0x00A5, KeyExchange.DH, Auth.DSS, Encryption.AES_256_GCM, Hash.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256 = new TlsCipher(0xC03E, KeyExchange.DH, Auth.DSS, Encryption.ARIA_128_CBC, Hash.SHA256, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256 = new TlsCipher(0xC058, KeyExchange.DH, Auth.DSS, Encryption.ARIA_128_GCM, Hash.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384 = new TlsCipher(0xC03F, KeyExchange.DH, Auth.DSS, Encryption.ARIA_256_CBC, Hash.SHA384, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384 = new TlsCipher(0xC059, KeyExchange.DH, Auth.DSS, Encryption.ARIA_256_GCM, Hash.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA = new TlsCipher(0x0042, KeyExchange.DH, Auth.DSS, Encryption.CAMELLIA_128_CBC, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256 = new TlsCipher(0x00BB, KeyExchange.DH, Auth.DSS, Encryption.CAMELLIA_128_CBC, Hash.SHA256, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256 = new TlsCipher(0xC082, KeyExchange.DH, Auth.DSS, Encryption.CAMELLIA_128_GCM, Hash.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA = new TlsCipher(0x0085, KeyExchange.DH, Auth.DSS, Encryption.CAMELLIA_256_CBC, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256 = new TlsCipher(0x00C1, KeyExchange.DH, Auth.DSS, Encryption.CAMELLIA_256_CBC, Hash.SHA256, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384 = new TlsCipher(0xC083, KeyExchange.DH, Auth.DSS, Encryption.CAMELLIA_256_GCM, Hash.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DH_DSS_WITH_DES_CBC_SHA = new TlsCipher(0x000C, KeyExchange.DH, Auth.DSS, Encryption.DES_CBC, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DH_DSS_WITH_SEED_CBC_SHA = new TlsCipher(0x0097, KeyExchange.DH, Auth.DSS, Encryption.SEED_CBC, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA = new TlsCipher(0x0011, KeyExchange.DHE, Auth.DSS, Encryption.DES40_CBC, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA = new TlsCipher(0x0013, KeyExchange.DHE, Auth.DSS, Encryption._3DES_EDE_CBC, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DHE_DSS_WITH_AES_128_CBC_SHA = new TlsCipher(0x0032, KeyExchange.DHE, Auth.DSS, Encryption.AES_128_CBC, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DHE_DSS_WITH_AES_128_CBC_SHA256 = new TlsCipher(0x0040, KeyExchange.DHE, Auth.DSS, Encryption.AES_128_CBC, Hash.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DHE_DSS_WITH_AES_128_GCM_SHA256 = new TlsCipher(0x00A2, KeyExchange.DHE, Auth.DSS, Encryption.AES_128_GCM, Hash.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DHE_DSS_WITH_AES_256_CBC_SHA = new TlsCipher(0x0038, KeyExchange.DHE, Auth.DSS, Encryption.AES_256_CBC, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DHE_DSS_WITH_AES_256_CBC_SHA256 = new TlsCipher(0x006A, KeyExchange.DHE, Auth.DSS, Encryption.AES_256_CBC, Hash.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DHE_DSS_WITH_AES_256_GCM_SHA384 = new TlsCipher(0x00A3, KeyExchange.DHE, Auth.DSS, Encryption.AES_256_GCM, Hash.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256 = new TlsCipher(0xC042, KeyExchange.DHE, Auth.DSS, Encryption.ARIA_128_CBC, Hash.SHA256, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256 = new TlsCipher(0xC056, KeyExchange.DHE, Auth.DSS, Encryption.ARIA_128_GCM, Hash.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384 = new TlsCipher(0xC043, KeyExchange.DHE, Auth.DSS, Encryption.ARIA_256_CBC, Hash.SHA384, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384 = new TlsCipher(0xC057, KeyExchange.DHE, Auth.DSS, Encryption.ARIA_256_GCM, Hash.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA = new TlsCipher(0x0044, KeyExchange.DHE, Auth.DSS, Encryption.CAMELLIA_128_CBC, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256 = new TlsCipher(0x00BD, KeyExchange.DHE, Auth.DSS, Encryption.CAMELLIA_128_CBC, Hash.SHA256, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256 = new TlsCipher(0xC080, KeyExchange.DHE, Auth.DSS, Encryption.CAMELLIA_128_GCM, Hash.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA = new TlsCipher(0x0087, KeyExchange.DHE, Auth.DSS, Encryption.CAMELLIA_256_CBC, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256 = new TlsCipher(0x00C3, KeyExchange.DHE, Auth.DSS, Encryption.CAMELLIA_256_CBC, Hash.SHA256, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384 = new TlsCipher(0xC081, KeyExchange.DHE, Auth.DSS, Encryption.CAMELLIA_256_GCM, Hash.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DHE_DSS_WITH_DES_CBC_SHA = new TlsCipher(0x0012, KeyExchange.DHE, Auth.DSS, Encryption.DES_CBC, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DHE_DSS_WITH_SEED_CBC_SHA = new TlsCipher(0x0099, KeyExchange.DHE, Auth.DSS, Encryption.SEED_CBC, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA = new TlsCipher(0x008F, KeyExchange.DHE, Auth.PSK, Encryption._3DES_EDE_CBC, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DHE_PSK_WITH_AES_128_CBC_SHA = new TlsCipher(0x0090, KeyExchange.DHE, Auth.PSK, Encryption.AES_128_CBC, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DHE_PSK_WITH_AES_128_CBC_SHA256 = new TlsCipher(0x00B2, KeyExchange.DHE, Auth.PSK, Encryption.AES_128_CBC, Hash.SHA256, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DHE_PSK_WITH_AES_128_CCM = new TlsCipher(0xC0A6, KeyExchange.DHE, Auth.PSK, Encryption.AES_128_CCM, Hash.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DHE_PSK_WITH_AES_128_GCM_SHA256 = new TlsCipher(0x00AA, KeyExchange.DHE, Auth.PSK, Encryption.AES_128_GCM, Hash.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DHE_PSK_WITH_AES_256_CBC_SHA = new TlsCipher(0x0091, KeyExchange.DHE, Auth.PSK, Encryption.AES_256_CBC, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DHE_PSK_WITH_AES_256_CBC_SHA384 = new TlsCipher(0x00B3, KeyExchange.DHE, Auth.PSK, Encryption.AES_256_CBC, Hash.SHA384, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DHE_PSK_WITH_AES_256_CCM = new TlsCipher(0xC0A7, KeyExchange.DHE, Auth.PSK, Encryption.AES_256_CCM, Hash.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DHE_PSK_WITH_AES_256_GCM_SHA384 = new TlsCipher(0x00AB, KeyExchange.DHE, Auth.PSK, Encryption.AES_256_GCM, Hash.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256 = new TlsCipher(0xC066, KeyExchange.DHE, Auth.PSK, Encryption.ARIA_128_CBC, Hash.SHA256, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256 = new TlsCipher(0xC06C, KeyExchange.DHE, Auth.PSK, Encryption.ARIA_128_GCM, Hash.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384 = new TlsCipher(0xC067, KeyExchange.DHE, Auth.PSK, Encryption.ARIA_256_CBC, Hash.SHA384, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384 = new TlsCipher(0xC06D, KeyExchange.DHE, Auth.PSK, Encryption.ARIA_256_GCM, Hash.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 = new TlsCipher(0xC096, KeyExchange.DHE, Auth.PSK, Encryption.CAMELLIA_128_CBC, Hash.SHA256, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256 = new TlsCipher(0xC090, KeyExchange.DHE, Auth.PSK, Encryption.CAMELLIA_128_GCM, Hash.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 = new TlsCipher(0xC097, KeyExchange.DHE, Auth.PSK, Encryption.CAMELLIA_256_CBC, Hash.SHA384, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384 = new TlsCipher(0xC091, KeyExchange.DHE, Auth.PSK, Encryption.CAMELLIA_256_GCM, Hash.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256 = new TlsCipher(0xCCAD, KeyExchange.DHE, Auth.PSK, Encryption.CHACHA20_POLY1305, Hash.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DHE_PSK_WITH_NULL_SHA = new TlsCipher(0x002D, KeyExchange.DHE, Auth.PSK, Encryption.NULL, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DHE_PSK_WITH_NULL_SHA256 = new TlsCipher(0x00B4, KeyExchange.DHE, Auth.PSK, Encryption.NULL, Hash.SHA256, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DHE_PSK_WITH_NULL_SHA384 = new TlsCipher(0x00B5, KeyExchange.DHE, Auth.PSK, Encryption.NULL, Hash.SHA384, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DHE_PSK_WITH_RC4_128_SHA = new TlsCipher(0x008E, KeyExchange.DHE, Auth.PSK, Encryption.RC4_128, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA = new TlsCipher(0x0014, KeyExchange.DHE, Auth.RSA, Encryption.DES40_CBC, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA = new TlsCipher(0x0016, KeyExchange.DHE, Auth.RSA, Encryption._3DES_EDE_CBC, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DHE_RSA_WITH_AES_128_CBC_SHA = new TlsCipher(0x0033, KeyExchange.DHE, Auth.RSA, Encryption.AES_128_CBC, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 = new TlsCipher(0x0067, KeyExchange.DHE, Auth.RSA, Encryption.AES_128_CBC, Hash.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DHE_RSA_WITH_AES_128_CCM = new TlsCipher(0xC09E, KeyExchange.DHE, Auth.RSA, Encryption.AES_128_CCM, Hash.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DHE_RSA_WITH_AES_128_CCM_8 = new TlsCipher(0xC0A2, KeyExchange.DHE, Auth.RSA, Encryption.AES_128_CCM_8, Hash.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 = new TlsCipher(0x009E, KeyExchange.DHE, Auth.RSA, Encryption.AES_128_GCM, Hash.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DHE_RSA_WITH_AES_256_CBC_SHA = new TlsCipher(0x0039, KeyExchange.DHE, Auth.RSA, Encryption.AES_256_CBC, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 = new TlsCipher(0x006B, KeyExchange.DHE, Auth.RSA, Encryption.AES_256_CBC, Hash.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DHE_RSA_WITH_AES_256_CCM = new TlsCipher(0xC09F, KeyExchange.DHE, Auth.RSA, Encryption.AES_256_CCM, Hash.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DHE_RSA_WITH_AES_256_CCM_8 = new TlsCipher(0xC0A3, KeyExchange.DHE, Auth.RSA, Encryption.AES_256_CCM_8, Hash.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 = new TlsCipher(0x009F, KeyExchange.DHE, Auth.RSA, Encryption.AES_256_GCM, Hash.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256 = new TlsCipher(0xC044, KeyExchange.DHE, Auth.RSA, Encryption.ARIA_128_CBC, Hash.SHA256, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256 = new TlsCipher(0xC052, KeyExchange.DHE, Auth.RSA, Encryption.ARIA_128_GCM, Hash.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384 = new TlsCipher(0xC045, KeyExchange.DHE, Auth.RSA, Encryption.ARIA_256_CBC, Hash.SHA384, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384 = new TlsCipher(0xC053, KeyExchange.DHE, Auth.RSA, Encryption.ARIA_256_GCM, Hash.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA = new TlsCipher(0x0045, KeyExchange.DHE, Auth.RSA, Encryption.CAMELLIA_128_CBC, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 = new TlsCipher(0x00BE, KeyExchange.DHE, Auth.RSA, Encryption.CAMELLIA_128_CBC, Hash.SHA256, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 = new TlsCipher(0xC07C, KeyExchange.DHE, Auth.RSA, Encryption.CAMELLIA_128_GCM, Hash.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA = new TlsCipher(0x0088, KeyExchange.DHE, Auth.RSA, Encryption.CAMELLIA_256_CBC, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256 = new TlsCipher(0x00C4, KeyExchange.DHE, Auth.RSA, Encryption.CAMELLIA_256_CBC, Hash.SHA256, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 = new TlsCipher(0xC07D, KeyExchange.DHE, Auth.RSA, Encryption.CAMELLIA_256_GCM, Hash.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = new TlsCipher(0xCCAA, KeyExchange.DHE, Auth.RSA, Encryption.CHACHA20_POLY1305, Hash.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DHE_RSA_WITH_DES_CBC_SHA = new TlsCipher(0x0015, KeyExchange.DHE, Auth.RSA, Encryption.DES_CBC, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DHE_RSA_WITH_SEED_CBC_SHA = new TlsCipher(0x009A, KeyExchange.DHE, Auth.RSA, Encryption.SEED_CBC, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA = new TlsCipher(0x000E, KeyExchange.DH, Auth.RSA, Encryption.DES40_CBC, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA = new TlsCipher(0x0010, KeyExchange.DH, Auth.RSA, Encryption._3DES_EDE_CBC, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DH_RSA_WITH_AES_128_CBC_SHA = new TlsCipher(0x0031, KeyExchange.DH, Auth.RSA, Encryption.AES_128_CBC, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DH_RSA_WITH_AES_128_CBC_SHA256 = new TlsCipher(0x003F, KeyExchange.DH, Auth.RSA, Encryption.AES_128_CBC, Hash.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DH_RSA_WITH_AES_128_GCM_SHA256 = new TlsCipher(0x00A0, KeyExchange.DH, Auth.RSA, Encryption.AES_128_GCM, Hash.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DH_RSA_WITH_AES_256_CBC_SHA = new TlsCipher(0x0037, KeyExchange.DH, Auth.RSA, Encryption.AES_256_CBC, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DH_RSA_WITH_AES_256_CBC_SHA256 = new TlsCipher(0x0069, KeyExchange.DH, Auth.RSA, Encryption.AES_256_CBC, Hash.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DH_RSA_WITH_AES_256_GCM_SHA384 = new TlsCipher(0x00A1, KeyExchange.DH, Auth.RSA, Encryption.AES_256_GCM, Hash.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256 = new TlsCipher(0xC040, KeyExchange.DH, Auth.RSA, Encryption.ARIA_128_CBC, Hash.SHA256, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256 = new TlsCipher(0xC054, KeyExchange.DH, Auth.RSA, Encryption.ARIA_128_GCM, Hash.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384 = new TlsCipher(0xC041, KeyExchange.DH, Auth.RSA, Encryption.ARIA_256_CBC, Hash.SHA384, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384 = new TlsCipher(0xC055, KeyExchange.DH, Auth.RSA, Encryption.ARIA_256_GCM, Hash.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA = new TlsCipher(0x0043, KeyExchange.DH, Auth.RSA, Encryption.CAMELLIA_128_CBC, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256 = new TlsCipher(0x00BC, KeyExchange.DH, Auth.RSA, Encryption.CAMELLIA_128_CBC, Hash.SHA256, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256 = new TlsCipher(0xC07E, KeyExchange.DH, Auth.RSA, Encryption.CAMELLIA_128_GCM, Hash.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA = new TlsCipher(0x0086, KeyExchange.DH, Auth.RSA, Encryption.CAMELLIA_256_CBC, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256 = new TlsCipher(0x00C2, KeyExchange.DH, Auth.RSA, Encryption.CAMELLIA_256_CBC, Hash.SHA256, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384 = new TlsCipher(0xC07F, KeyExchange.DH, Auth.RSA, Encryption.CAMELLIA_256_GCM, Hash.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DH_RSA_WITH_DES_CBC_SHA = new TlsCipher(0x000F, KeyExchange.DH, Auth.RSA, Encryption.DES_CBC, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_DH_RSA_WITH_SEED_CBC_SHA = new TlsCipher(0x0098, KeyExchange.DH, Auth.RSA, Encryption.SEED_CBC, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECCPWD_WITH_AES_128_CCM_SHA256 = new TlsCipher(0xC0B2, KeyExchange.ECCPWD, Auth.ECCPWD, Encryption.AES_128_CCM, Hash.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECCPWD_WITH_AES_128_GCM_SHA256 = new TlsCipher(0xC0B0, KeyExchange.ECCPWD, Auth.ECCPWD, Encryption.AES_128_GCM, Hash.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECCPWD_WITH_AES_256_CCM_SHA384 = new TlsCipher(0xC0B3, KeyExchange.ECCPWD, Auth.ECCPWD, Encryption.AES_256_CCM, Hash.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECCPWD_WITH_AES_256_GCM_SHA384 = new TlsCipher(0xC0B1, KeyExchange.ECCPWD, Auth.ECCPWD, Encryption.AES_256_GCM, Hash.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDH_ANON_WITH_3DES_EDE_CBC_SHA = new TlsCipher(0xC017, KeyExchange.ECDH, Auth.ANON, Encryption._3DES_EDE_CBC, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDH_ANON_WITH_AES_128_CBC_SHA = new TlsCipher(0xC018, KeyExchange.ECDH, Auth.ANON, Encryption.AES_128_CBC, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDH_ANON_WITH_AES_256_CBC_SHA = new TlsCipher(0xC019, KeyExchange.ECDH, Auth.ANON, Encryption.AES_256_CBC, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDH_ANON_WITH_NULL_SHA = new TlsCipher(0xC015, KeyExchange.ECDH, Auth.ANON, Encryption.NULL, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDH_ANON_WITH_RC4_128_SHA = new TlsCipher(0xC016, KeyExchange.ECDH, Auth.ANON, Encryption.RC4_128, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA = new TlsCipher(0xC003, KeyExchange.ECDH, Auth.ECDSA, Encryption._3DES_EDE_CBC, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA = new TlsCipher(0xC004, KeyExchange.ECDH, Auth.ECDSA, Encryption.AES_128_CBC, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256 = new TlsCipher(0xC025, KeyExchange.ECDH, Auth.ECDSA, Encryption.AES_128_CBC, Hash.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256 = new TlsCipher(0xC02D, KeyExchange.ECDH, Auth.ECDSA, Encryption.AES_128_GCM, Hash.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA = new TlsCipher(0xC005, KeyExchange.ECDH, Auth.ECDSA, Encryption.AES_256_CBC, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384 = new TlsCipher(0xC026, KeyExchange.ECDH, Auth.ECDSA, Encryption.AES_256_CBC, Hash.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384 = new TlsCipher(0xC02E, KeyExchange.ECDH, Auth.ECDSA, Encryption.AES_256_GCM, Hash.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256 = new TlsCipher(0xC04A, KeyExchange.ECDH, Auth.ECDSA, Encryption.ARIA_128_CBC, Hash.SHA256, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256 = new TlsCipher(0xC05E, KeyExchange.ECDH, Auth.ECDSA, Encryption.ARIA_128_GCM, Hash.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384 = new TlsCipher(0xC04B, KeyExchange.ECDH, Auth.ECDSA, Encryption.ARIA_256_CBC, Hash.SHA384, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384 = new TlsCipher(0xC05F, KeyExchange.ECDH, Auth.ECDSA, Encryption.ARIA_256_GCM, Hash.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 = new TlsCipher(0xC074, KeyExchange.ECDH, Auth.ECDSA, Encryption.CAMELLIA_128_CBC, Hash.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 = new TlsCipher(0xC088, KeyExchange.ECDH, Auth.ECDSA, Encryption.CAMELLIA_128_GCM, Hash.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 = new TlsCipher(0xC075, KeyExchange.ECDH, Auth.ECDSA, Encryption.CAMELLIA_256_CBC, Hash.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 = new TlsCipher(0xC089, KeyExchange.ECDH, Auth.ECDSA, Encryption.CAMELLIA_256_GCM, Hash.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDH_ECDSA_WITH_NULL_SHA = new TlsCipher(0xC001, KeyExchange.ECDH, Auth.ECDSA, Encryption.NULL, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDH_ECDSA_WITH_RC4_128_SHA = new TlsCipher(0xC002, KeyExchange.ECDH, Auth.ECDSA, Encryption.RC4_128, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA = new TlsCipher(0xC008, KeyExchange.ECDHE, Auth.ECDSA, Encryption._3DES_EDE_CBC, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA = new TlsCipher(0xC009, KeyExchange.ECDHE, Auth.ECDSA, Encryption.AES_128_CBC, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 = new TlsCipher(0xC023, KeyExchange.ECDHE, Auth.ECDSA, Encryption.AES_128_CBC, Hash.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDHE_ECDSA_WITH_AES_128_CCM = new TlsCipher(0xC0AC, KeyExchange.ECDHE, Auth.ECDSA, Encryption.AES_128_CCM, Hash.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 = new TlsCipher(0xC0AE, KeyExchange.ECDHE, Auth.ECDSA, Encryption.AES_128_CCM_8, Hash.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = new TlsCipher(0xC02B, KeyExchange.ECDHE, Auth.ECDSA, Encryption.AES_128_GCM, Hash.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA = new TlsCipher(0xC00A, KeyExchange.ECDHE, Auth.ECDSA, Encryption.AES_256_CBC, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 = new TlsCipher(0xC024, KeyExchange.ECDHE, Auth.ECDSA, Encryption.AES_256_CBC, Hash.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDHE_ECDSA_WITH_AES_256_CCM = new TlsCipher(0xC0AD, KeyExchange.ECDHE, Auth.ECDSA, Encryption.AES_256_CCM, Hash.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8 = new TlsCipher(0xC0AF, KeyExchange.ECDHE, Auth.ECDSA, Encryption.AES_256_CCM_8, Hash.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = new TlsCipher(0xC02C, KeyExchange.ECDHE, Auth.ECDSA, Encryption.AES_256_GCM, Hash.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256 = new TlsCipher(0xC048, KeyExchange.ECDHE, Auth.ECDSA, Encryption.ARIA_128_CBC, Hash.SHA256, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256 = new TlsCipher(0xC05C, KeyExchange.ECDHE, Auth.ECDSA, Encryption.ARIA_128_GCM, Hash.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384 = new TlsCipher(0xC049, KeyExchange.ECDHE, Auth.ECDSA, Encryption.ARIA_256_CBC, Hash.SHA384, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384 = new TlsCipher(0xC05D, KeyExchange.ECDHE, Auth.ECDSA, Encryption.ARIA_256_GCM, Hash.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 = new TlsCipher(0xC072, KeyExchange.ECDHE, Auth.ECDSA, Encryption.CAMELLIA_128_CBC, Hash.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 = new TlsCipher(0xC086, KeyExchange.ECDHE, Auth.ECDSA, Encryption.CAMELLIA_128_GCM, Hash.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 = new TlsCipher(0xC073, KeyExchange.ECDHE, Auth.ECDSA, Encryption.CAMELLIA_256_CBC, Hash.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 = new TlsCipher(0xC087, KeyExchange.ECDHE, Auth.ECDSA, Encryption.CAMELLIA_256_GCM, Hash.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = new TlsCipher(0xCCA9, KeyExchange.ECDHE, Auth.ECDSA, Encryption.CHACHA20_POLY1305, Hash.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDHE_ECDSA_WITH_NULL_SHA = new TlsCipher(0xC006, KeyExchange.ECDHE, Auth.ECDSA, Encryption.NULL, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDHE_ECDSA_WITH_RC4_128_SHA = new TlsCipher(0xC007, KeyExchange.ECDHE, Auth.ECDSA, Encryption.RC4_128, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA = new TlsCipher(0xC034, KeyExchange.ECDHE, Auth.PSK, Encryption._3DES_EDE_CBC, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA = new TlsCipher(0xC035, KeyExchange.ECDHE, Auth.PSK, Encryption.AES_128_CBC, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256 = new TlsCipher(0xC037, KeyExchange.ECDHE, Auth.PSK, Encryption.AES_128_CBC, Hash.SHA256, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256 = new TlsCipher(0xD003, KeyExchange.ECDHE, Auth.PSK, Encryption.AES_128_CCM_8, Hash.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256 = new TlsCipher(0xD005, KeyExchange.ECDHE, Auth.PSK, Encryption.AES_128_CCM, Hash.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256 = new TlsCipher(0xD001, KeyExchange.ECDHE, Auth.PSK, Encryption.AES_128_GCM, Hash.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA = new TlsCipher(0xC036, KeyExchange.ECDHE, Auth.PSK, Encryption.AES_256_CBC, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384 = new TlsCipher(0xC038, KeyExchange.ECDHE, Auth.PSK, Encryption.AES_256_CBC, Hash.SHA384, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384 = new TlsCipher(0xD002, KeyExchange.ECDHE, Auth.PSK, Encryption.AES_256_GCM, Hash.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256 = new TlsCipher(0xC070, KeyExchange.ECDHE, Auth.PSK, Encryption.ARIA_128_CBC, Hash.SHA256, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384 = new TlsCipher(0xC071, KeyExchange.ECDHE, Auth.PSK, Encryption.ARIA_256_CBC, Hash.SHA384, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 = new TlsCipher(0xC09A, KeyExchange.ECDHE, Auth.PSK, Encryption.CAMELLIA_128_CBC, Hash.SHA256, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 = new TlsCipher(0xC09B, KeyExchange.ECDHE, Auth.PSK, Encryption.CAMELLIA_256_CBC, Hash.SHA384, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256 = new TlsCipher(0xCCAC, KeyExchange.ECDHE, Auth.PSK, Encryption.CHACHA20_POLY1305, Hash.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDHE_PSK_WITH_NULL_SHA = new TlsCipher(0xC039, KeyExchange.ECDHE, Auth.PSK, Encryption.NULL, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDHE_PSK_WITH_NULL_SHA256 = new TlsCipher(0xC03A, KeyExchange.ECDHE, Auth.PSK, Encryption.NULL, Hash.SHA256, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDHE_PSK_WITH_NULL_SHA384 = new TlsCipher(0xC03B, KeyExchange.ECDHE, Auth.PSK, Encryption.NULL, Hash.SHA384, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDHE_PSK_WITH_RC4_128_SHA = new TlsCipher(0xC033, KeyExchange.ECDHE, Auth.PSK, Encryption.RC4_128, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA = new TlsCipher(0xC012, KeyExchange.ECDHE, Auth.RSA, Encryption._3DES_EDE_CBC, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA = new TlsCipher(0xC013, KeyExchange.ECDHE, Auth.RSA, Encryption.AES_128_CBC, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 = new TlsCipher(0xC027, KeyExchange.ECDHE, Auth.RSA, Encryption.AES_128_CBC, Hash.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = new TlsCipher(0xC02F, KeyExchange.ECDHE, Auth.RSA, Encryption.AES_128_GCM, Hash.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA = new TlsCipher(0xC014, KeyExchange.ECDHE, Auth.RSA, Encryption.AES_256_CBC, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 = new TlsCipher(0xC028, KeyExchange.ECDHE, Auth.RSA, Encryption.AES_256_CBC, Hash.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = new TlsCipher(0xC030, KeyExchange.ECDHE, Auth.RSA, Encryption.AES_256_GCM, Hash.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256 = new TlsCipher(0xC04C, KeyExchange.ECDHE, Auth.RSA, Encryption.ARIA_128_CBC, Hash.SHA256, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256 = new TlsCipher(0xC060, KeyExchange.ECDHE, Auth.RSA, Encryption.ARIA_128_GCM, Hash.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384 = new TlsCipher(0xC04D, KeyExchange.ECDHE, Auth.RSA, Encryption.ARIA_256_CBC, Hash.SHA384, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384 = new TlsCipher(0xC061, KeyExchange.ECDHE, Auth.RSA, Encryption.ARIA_256_GCM, Hash.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 = new TlsCipher(0xC076, KeyExchange.ECDHE, Auth.RSA, Encryption.CAMELLIA_128_CBC, Hash.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 = new TlsCipher(0xC08A, KeyExchange.ECDHE, Auth.RSA, Encryption.CAMELLIA_128_GCM, Hash.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384 = new TlsCipher(0xC077, KeyExchange.ECDHE, Auth.RSA, Encryption.CAMELLIA_256_CBC, Hash.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 = new TlsCipher(0xC08B, KeyExchange.ECDHE, Auth.RSA, Encryption.CAMELLIA_256_GCM, Hash.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = new TlsCipher(0xCCA8, KeyExchange.ECDHE, Auth.RSA, Encryption.CHACHA20_POLY1305, Hash.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDHE_RSA_WITH_NULL_SHA = new TlsCipher(0xC010, KeyExchange.ECDHE, Auth.RSA, Encryption.NULL, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDHE_RSA_WITH_RC4_128_SHA = new TlsCipher(0xC011, KeyExchange.ECDHE, Auth.RSA, Encryption.RC4_128, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA = new TlsCipher(0xC00D, KeyExchange.ECDH, Auth.RSA, Encryption._3DES_EDE_CBC, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDH_RSA_WITH_AES_128_CBC_SHA = new TlsCipher(0xC00E, KeyExchange.ECDH, Auth.RSA, Encryption.AES_128_CBC, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256 = new TlsCipher(0xC029, KeyExchange.ECDH, Auth.RSA, Encryption.AES_128_CBC, Hash.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256 = new TlsCipher(0xC031, KeyExchange.ECDH, Auth.RSA, Encryption.AES_128_GCM, Hash.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDH_RSA_WITH_AES_256_CBC_SHA = new TlsCipher(0xC00F, KeyExchange.ECDH, Auth.RSA, Encryption.AES_256_CBC, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384 = new TlsCipher(0xC02A, KeyExchange.ECDH, Auth.RSA, Encryption.AES_256_CBC, Hash.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384 = new TlsCipher(0xC032, KeyExchange.ECDH, Auth.RSA, Encryption.AES_256_GCM, Hash.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256 = new TlsCipher(0xC04E, KeyExchange.ECDH, Auth.RSA, Encryption.ARIA_128_CBC, Hash.SHA256, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256 = new TlsCipher(0xC062, KeyExchange.ECDH, Auth.RSA, Encryption.ARIA_128_GCM, Hash.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384 = new TlsCipher(0xC04F, KeyExchange.ECDH, Auth.RSA, Encryption.ARIA_256_CBC, Hash.SHA384, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384 = new TlsCipher(0xC063, KeyExchange.ECDH, Auth.RSA, Encryption.ARIA_256_GCM, Hash.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256 = new TlsCipher(0xC078, KeyExchange.ECDH, Auth.RSA, Encryption.CAMELLIA_128_CBC, Hash.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256 = new TlsCipher(0xC08C, KeyExchange.ECDH, Auth.RSA, Encryption.CAMELLIA_128_GCM, Hash.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384 = new TlsCipher(0xC079, KeyExchange.ECDH, Auth.RSA, Encryption.CAMELLIA_256_CBC, Hash.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384 = new TlsCipher(0xC08D, KeyExchange.ECDH, Auth.RSA, Encryption.CAMELLIA_256_GCM, Hash.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDH_RSA_WITH_NULL_SHA = new TlsCipher(0xC00B, KeyExchange.ECDH, Auth.RSA, Encryption.NULL, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_ECDH_RSA_WITH_RC4_128_SHA = new TlsCipher(0xC00C, KeyExchange.ECDH, Auth.RSA, Encryption.RC4_128, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_GOSTR341112_256_WITH_28147_CNT_IMIT = new TlsCipher(0xC102, KeyExchange.GOSTR341112_256, Auth.GOSTR341012, Encryption._28147_CNT, Hash.GOSTR341112, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC = new TlsCipher(0xC100, KeyExchange.GOSTR341112_256, Auth.GOSTR341012, Encryption.KUZNYECHIK_CTR, Hash.GOSTR341112, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L = new TlsCipher(0xC103, KeyExchange.ECDHE, Auth.NULL, Encryption.KUZNYECHIK_MGM_L, Hash.NULL, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S = new TlsCipher(0xC105, KeyExchange.ECDHE, Auth.NULL, Encryption.KUZNYECHIK_MGM_S, Hash.NULL, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC = new TlsCipher(0xC101, KeyExchange.GOSTR341112_256, Auth.GOSTR341012, Encryption.MAGMA_CTR, Hash.GOSTR341112, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_GOSTR341112_256_WITH_MAGMA_MGM_L = new TlsCipher(0xC104, KeyExchange.ECDHE, Auth.NULL, Encryption.MAGMA_MGM_L, Hash.NULL, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_GOSTR341112_256_WITH_MAGMA_MGM_S = new TlsCipher(0xC106, KeyExchange.ECDHE, Auth.NULL, Encryption.MAGMA_MGM_S, Hash.NULL, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5 = new TlsCipher(0x0029, KeyExchange.KRB5, Auth.KRB5, Encryption.DES_CBC_40, Hash.MD5, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA = new TlsCipher(0x0026, KeyExchange.KRB5, Auth.KRB5, Encryption.DES_CBC_40, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5 = new TlsCipher(0x002A, KeyExchange.KRB5, Auth.KRB5, Encryption.RC2_CBC_40, Hash.MD5, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA = new TlsCipher(0x0027, KeyExchange.KRB5, Auth.KRB5, Encryption.RC2_CBC_40, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_KRB5_EXPORT_WITH_RC4_40_MD5 = new TlsCipher(0x002B, KeyExchange.KRB5, Auth.KRB5, Encryption.RC4_40, Hash.MD5, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_KRB5_EXPORT_WITH_RC4_40_SHA = new TlsCipher(0x0028, KeyExchange.KRB5, Auth.KRB5, Encryption.RC4_40, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_KRB5_WITH_3DES_EDE_CBC_MD5 = new TlsCipher(0x0023, KeyExchange.KRB5, Auth.KRB5, Encryption._3DES_EDE_CBC, Hash.MD5, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_KRB5_WITH_3DES_EDE_CBC_SHA = new TlsCipher(0x001F, KeyExchange.KRB5, Auth.KRB5, Encryption._3DES_EDE_CBC, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_KRB5_WITH_DES_CBC_MD5 = new TlsCipher(0x0022, KeyExchange.KRB5, Auth.KRB5, Encryption.DES_CBC, Hash.MD5, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_KRB5_WITH_DES_CBC_SHA = new TlsCipher(0x001E, KeyExchange.KRB5, Auth.KRB5, Encryption.DES_CBC, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_KRB5_WITH_IDEA_CBC_MD5 = new TlsCipher(0x0025, KeyExchange.KRB5, Auth.KRB5, Encryption.IDEA_CBC, Hash.MD5, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_KRB5_WITH_IDEA_CBC_SHA = new TlsCipher(0x0021, KeyExchange.KRB5, Auth.KRB5, Encryption.IDEA_CBC, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_KRB5_WITH_RC4_128_MD5 = new TlsCipher(0x0024, KeyExchange.KRB5, Auth.KRB5, Encryption.RC4_128, Hash.MD5, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_KRB5_WITH_RC4_128_SHA = new TlsCipher(0x0020, KeyExchange.KRB5, Auth.KRB5, Encryption.RC4_128, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_NULL_WITH_NULL_NULL = new TlsCipher(0x0000, KeyExchange.NULL, Auth.NULL, Encryption.NULL, Hash.NULL, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_PSK_DHE_WITH_AES_128_CCM_8 = new TlsCipher(0xC0AA, KeyExchange.DHE, Auth.PSK, Encryption.AES_128_CCM_8, Hash.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_PSK_DHE_WITH_AES_256_CCM_8 = new TlsCipher(0xC0AB, KeyExchange.DHE, Auth.PSK, Encryption.AES_256_CCM_8, Hash.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_PSK_WITH_3DES_EDE_CBC_SHA = new TlsCipher(0x008B, KeyExchange.PSK, Auth.PSK, Encryption._3DES_EDE_CBC, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_PSK_WITH_AES_128_CBC_SHA = new TlsCipher(0x008C, KeyExchange.PSK, Auth.PSK, Encryption.AES_128_CBC, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_PSK_WITH_AES_128_CBC_SHA256 = new TlsCipher(0x00AE, KeyExchange.PSK, Auth.PSK, Encryption.AES_128_CBC, Hash.SHA256, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_PSK_WITH_AES_128_CCM = new TlsCipher(0xC0A4, KeyExchange.PSK, Auth.PSK, Encryption.AES_128_CCM, Hash.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_PSK_WITH_AES_128_CCM_8 = new TlsCipher(0xC0A8, KeyExchange.PSK, Auth.PSK, Encryption.AES_128_CCM_8, Hash.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_PSK_WITH_AES_128_GCM_SHA256 = new TlsCipher(0x00A8, KeyExchange.PSK, Auth.PSK, Encryption.AES_128_GCM, Hash.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_PSK_WITH_AES_256_CBC_SHA = new TlsCipher(0x008D, KeyExchange.PSK, Auth.PSK, Encryption.AES_256_CBC, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_PSK_WITH_AES_256_CBC_SHA384 = new TlsCipher(0x00AF, KeyExchange.PSK, Auth.PSK, Encryption.AES_256_CBC, Hash.SHA384, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_PSK_WITH_AES_256_CCM = new TlsCipher(0xC0A5, KeyExchange.PSK, Auth.PSK, Encryption.AES_256_CCM, Hash.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_PSK_WITH_AES_256_CCM_8 = new TlsCipher(0xC0A9, KeyExchange.PSK, Auth.PSK, Encryption.AES_256_CCM_8, Hash.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_PSK_WITH_AES_256_GCM_SHA384 = new TlsCipher(0x00A9, KeyExchange.PSK, Auth.PSK, Encryption.AES_256_GCM, Hash.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_PSK_WITH_ARIA_128_CBC_SHA256 = new TlsCipher(0xC064, KeyExchange.PSK, Auth.PSK, Encryption.ARIA_128_CBC, Hash.SHA256, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_PSK_WITH_ARIA_128_GCM_SHA256 = new TlsCipher(0xC06A, KeyExchange.PSK, Auth.PSK, Encryption.ARIA_128_GCM, Hash.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_PSK_WITH_ARIA_256_CBC_SHA384 = new TlsCipher(0xC065, KeyExchange.PSK, Auth.PSK, Encryption.ARIA_256_CBC, Hash.SHA384, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_PSK_WITH_ARIA_256_GCM_SHA384 = new TlsCipher(0xC06B, KeyExchange.PSK, Auth.PSK, Encryption.ARIA_256_GCM, Hash.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256 = new TlsCipher(0xC094, KeyExchange.PSK, Auth.PSK, Encryption.CAMELLIA_128_CBC, Hash.SHA256, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256 = new TlsCipher(0xC08E, KeyExchange.PSK, Auth.PSK, Encryption.CAMELLIA_128_GCM, Hash.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384 = new TlsCipher(0xC095, KeyExchange.PSK, Auth.PSK, Encryption.CAMELLIA_256_CBC, Hash.SHA384, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384 = new TlsCipher(0xC08F, KeyExchange.PSK, Auth.PSK, Encryption.CAMELLIA_256_GCM, Hash.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_PSK_WITH_CHACHA20_POLY1305_SHA256 = new TlsCipher(0xCCAB, KeyExchange.PSK, Auth.PSK, Encryption.CHACHA20_POLY1305, Hash.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_PSK_WITH_NULL_SHA = new TlsCipher(0x002C, KeyExchange.PSK, Auth.PSK, Encryption.NULL, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_PSK_WITH_NULL_SHA256 = new TlsCipher(0x00B0, KeyExchange.PSK, Auth.PSK, Encryption.NULL, Hash.SHA256, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_PSK_WITH_NULL_SHA384 = new TlsCipher(0x00B1, KeyExchange.PSK, Auth.PSK, Encryption.NULL, Hash.SHA384, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_PSK_WITH_RC4_128_SHA = new TlsCipher(0x008A, KeyExchange.PSK, Auth.PSK, Encryption.RC4_128, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_RSA_EXPORT_WITH_DES40_CBC_SHA = new TlsCipher(0x0008, KeyExchange.RSA, Auth.RSA, Encryption.DES40_CBC, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5 = new TlsCipher(0x0006, KeyExchange.RSA, Auth.RSA, Encryption.RC2_CBC_40, Hash.MD5, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_RSA_EXPORT_WITH_RC4_40_MD5 = new TlsCipher(0x0003, KeyExchange.RSA, Auth.RSA, Encryption.RC4_40, Hash.MD5, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA = new TlsCipher(0x0093, KeyExchange.RSA, Auth.PSK, Encryption._3DES_EDE_CBC, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_RSA_PSK_WITH_AES_128_CBC_SHA = new TlsCipher(0x0094, KeyExchange.RSA, Auth.PSK, Encryption.AES_128_CBC, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_RSA_PSK_WITH_AES_128_CBC_SHA256 = new TlsCipher(0x00B6, KeyExchange.RSA, Auth.PSK, Encryption.AES_128_CBC, Hash.SHA256, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_RSA_PSK_WITH_AES_128_GCM_SHA256 = new TlsCipher(0x00AC, KeyExchange.RSA, Auth.PSK, Encryption.AES_128_GCM, Hash.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_RSA_PSK_WITH_AES_256_CBC_SHA = new TlsCipher(0x0095, KeyExchange.RSA, Auth.PSK, Encryption.AES_256_CBC, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_RSA_PSK_WITH_AES_256_CBC_SHA384 = new TlsCipher(0x00B7, KeyExchange.RSA, Auth.PSK, Encryption.AES_256_CBC, Hash.SHA384, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_RSA_PSK_WITH_AES_256_GCM_SHA384 = new TlsCipher(0x00AD, KeyExchange.RSA, Auth.PSK, Encryption.AES_256_GCM, Hash.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256 = new TlsCipher(0xC068, KeyExchange.RSA, Auth.PSK, Encryption.ARIA_128_CBC, Hash.SHA256, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256 = new TlsCipher(0xC06E, KeyExchange.RSA, Auth.PSK, Encryption.ARIA_128_GCM, Hash.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384 = new TlsCipher(0xC069, KeyExchange.RSA, Auth.PSK, Encryption.ARIA_256_CBC, Hash.SHA384, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384 = new TlsCipher(0xC06F, KeyExchange.RSA, Auth.PSK, Encryption.ARIA_256_GCM, Hash.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256 = new TlsCipher(0xC098, KeyExchange.RSA, Auth.PSK, Encryption.CAMELLIA_128_CBC, Hash.SHA256, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256 = new TlsCipher(0xC092, KeyExchange.RSA, Auth.PSK, Encryption.CAMELLIA_128_GCM, Hash.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384 = new TlsCipher(0xC099, KeyExchange.RSA, Auth.PSK, Encryption.CAMELLIA_256_CBC, Hash.SHA384, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384 = new TlsCipher(0xC093, KeyExchange.RSA, Auth.PSK, Encryption.CAMELLIA_256_GCM, Hash.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256 = new TlsCipher(0xCCAE, KeyExchange.RSA, Auth.PSK, Encryption.CHACHA20_POLY1305, Hash.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_RSA_PSK_WITH_NULL_SHA = new TlsCipher(0x002E, KeyExchange.RSA, Auth.PSK, Encryption.NULL, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_RSA_PSK_WITH_NULL_SHA256 = new TlsCipher(0x00B8, KeyExchange.RSA, Auth.PSK, Encryption.NULL, Hash.SHA256, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_RSA_PSK_WITH_NULL_SHA384 = new TlsCipher(0x00B9, KeyExchange.RSA, Auth.PSK, Encryption.NULL, Hash.SHA384, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_RSA_PSK_WITH_RC4_128_SHA = new TlsCipher(0x0092, KeyExchange.RSA, Auth.PSK, Encryption.RC4_128, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_RSA_WITH_3DES_EDE_CBC_SHA = new TlsCipher(0x000A, KeyExchange.RSA, Auth.RSA, Encryption._3DES_EDE_CBC, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_RSA_WITH_AES_128_CBC_SHA = new TlsCipher(0x002F, KeyExchange.RSA, Auth.RSA, Encryption.AES_128_CBC, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_RSA_WITH_AES_128_CBC_SHA256 = new TlsCipher(0x003C, KeyExchange.RSA, Auth.RSA, Encryption.AES_128_CBC, Hash.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_RSA_WITH_AES_128_CCM = new TlsCipher(0xC09C, KeyExchange.RSA, Auth.RSA, Encryption.AES_128_CCM, Hash.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_RSA_WITH_AES_128_CCM_8 = new TlsCipher(0xC0A0, KeyExchange.RSA, Auth.RSA, Encryption.AES_128_CCM_8, Hash.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_RSA_WITH_AES_128_GCM_SHA256 = new TlsCipher(0x009C, KeyExchange.RSA, Auth.RSA, Encryption.AES_128_GCM, Hash.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_RSA_WITH_AES_256_CBC_SHA = new TlsCipher(0x0035, KeyExchange.RSA, Auth.RSA, Encryption.AES_256_CBC, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_RSA_WITH_AES_256_CBC_SHA256 = new TlsCipher(0x003D, KeyExchange.RSA, Auth.RSA, Encryption.AES_256_CBC, Hash.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_RSA_WITH_AES_256_CCM = new TlsCipher(0xC09D, KeyExchange.RSA, Auth.RSA, Encryption.AES_256_CCM, Hash.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_RSA_WITH_AES_256_CCM_8 = new TlsCipher(0xC0A1, KeyExchange.RSA, Auth.RSA, Encryption.AES_256_CCM_8, Hash.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_RSA_WITH_AES_256_GCM_SHA384 = new TlsCipher(0x009D, KeyExchange.RSA, Auth.RSA, Encryption.AES_256_GCM, Hash.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_RSA_WITH_ARIA_128_CBC_SHA256 = new TlsCipher(0xC03C, KeyExchange.RSA, Auth.RSA, Encryption.ARIA_128_CBC, Hash.SHA256, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_RSA_WITH_ARIA_128_GCM_SHA256 = new TlsCipher(0xC050, KeyExchange.RSA, Auth.RSA, Encryption.ARIA_128_GCM, Hash.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_RSA_WITH_ARIA_256_CBC_SHA384 = new TlsCipher(0xC03D, KeyExchange.RSA, Auth.RSA, Encryption.ARIA_256_CBC, Hash.SHA384, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_RSA_WITH_ARIA_256_GCM_SHA384 = new TlsCipher(0xC051, KeyExchange.RSA, Auth.RSA, Encryption.ARIA_256_GCM, Hash.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_RSA_WITH_CAMELLIA_128_CBC_SHA = new TlsCipher(0x0041, KeyExchange.RSA, Auth.RSA, Encryption.CAMELLIA_128_CBC, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256 = new TlsCipher(0x00BA, KeyExchange.RSA, Auth.RSA, Encryption.CAMELLIA_128_CBC, Hash.SHA256, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256 = new TlsCipher(0xC07A, KeyExchange.RSA, Auth.RSA, Encryption.CAMELLIA_128_GCM, Hash.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_RSA_WITH_CAMELLIA_256_CBC_SHA = new TlsCipher(0x0084, KeyExchange.RSA, Auth.RSA, Encryption.CAMELLIA_256_CBC, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256 = new TlsCipher(0x00C0, KeyExchange.RSA, Auth.RSA, Encryption.CAMELLIA_256_CBC, Hash.SHA256, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384 = new TlsCipher(0xC07B, KeyExchange.RSA, Auth.RSA, Encryption.CAMELLIA_256_GCM, Hash.SHA384, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_RSA_WITH_DES_CBC_SHA = new TlsCipher(0x0009, KeyExchange.RSA, Auth.RSA, Encryption.DES_CBC, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_RSA_WITH_IDEA_CBC_SHA = new TlsCipher(0x0007, KeyExchange.RSA, Auth.RSA, Encryption.IDEA_CBC, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_RSA_WITH_NULL_MD5 = new TlsCipher(0x0001, KeyExchange.RSA, Auth.RSA, Encryption.NULL, Hash.MD5, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_RSA_WITH_NULL_SHA = new TlsCipher(0x0002, KeyExchange.RSA, Auth.RSA, Encryption.NULL, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_RSA_WITH_NULL_SHA256 = new TlsCipher(0x003B, KeyExchange.RSA, Auth.RSA, Encryption.NULL, Hash.SHA256, List.of(TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_RSA_WITH_RC4_128_MD5 = new TlsCipher(0x0004, KeyExchange.RSA, Auth.RSA, Encryption.RC4_128, Hash.MD5, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_RSA_WITH_RC4_128_SHA = new TlsCipher(0x0005, KeyExchange.RSA, Auth.RSA, Encryption.RC4_128, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_RSA_WITH_SEED_CBC_SHA = new TlsCipher(0x0096, KeyExchange.RSA, Auth.RSA, Encryption.SEED_CBC, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_SHA256_SHA256 = new TlsCipher(0xC0B4, KeyExchange.NULL, Auth.SHA256, Encryption.NULL, Hash.SHA256, List.of(TlsVersion.TLS13));
    private static final TlsCipher TLS_SHA384_SHA384 = new TlsCipher(0xC0B5, KeyExchange.NULL, Auth.SHA384, Encryption.NULL, Hash.SHA384, List.of(TlsVersion.TLS13));
    private static final TlsCipher TLS_SM4_CCM_SM3 = new TlsCipher(0x00C7, KeyExchange.NULL, Auth.NULL, Encryption.SM4_CCM, Hash.SM3, List.of(TlsVersion.TLS13));
    private static final TlsCipher TLS_SM4_GCM_SM3 = new TlsCipher(0x00C6, KeyExchange.NULL, Auth.NULL, Encryption.SM4_GCM, Hash.SM3, List.of(TlsVersion.TLS13));
    private static final TlsCipher TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA = new TlsCipher(0xC01C, KeyExchange.SRP, Auth.SHA_DSS, Encryption._3DES_EDE_CBC, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA = new TlsCipher(0xC01F, KeyExchange.SRP, Auth.SHA_DSS, Encryption.AES_128_CBC, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA = new TlsCipher(0xC022, KeyExchange.SRP, Auth.SHA_DSS, Encryption.AES_256_CBC, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA = new TlsCipher(0xC01B, KeyExchange.SRP, Auth.SHA_RSA, Encryption._3DES_EDE_CBC, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA = new TlsCipher(0xC01E, KeyExchange.SRP, Auth.SHA_RSA, Encryption.AES_128_CBC, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA = new TlsCipher(0xC021, KeyExchange.SRP, Auth.SHA_RSA, Encryption.AES_256_CBC, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA = new TlsCipher(0xC01A, KeyExchange.SRP, Auth.SHA, Encryption._3DES_EDE_CBC, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_SRP_SHA_WITH_AES_128_CBC_SHA = new TlsCipher(0xC01D, KeyExchange.SRP, Auth.SHA, Encryption.AES_128_CBC, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
    private static final TlsCipher TLS_SRP_SHA_WITH_AES_256_CBC_SHA = new TlsCipher(0xC020, KeyExchange.SRP, Auth.SHA, Encryption.AES_256_CBC, Hash.SHA, List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13));
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
    //</editor-fold>

    public enum KeyExchange {
        DH,
        DHE,
        ECCPWD,
        ECDH,
        ECDHE,
        GOSTR341112_256,
        KRB5,
        NULL,
        PSK,
        RSA,
        SRP
    }

    public enum Auth {
        ANON,
        DSS,
        ECCPWD,
        ECDSA,
        GOSTR341012,
        KRB5,
        NULL,
        PSK,
        RSA,
        SHA,
        SHA256,
        SHA384,
        SHA_DSS,
        SHA_RSA
    }

    public enum Encryption {
        AES_128_CBC,
        AES_128_CCM,
        AES_128_CCM_8,
        AES_128_GCM,
        AES_256_CBC,
        AES_256_CCM,
        AES_256_CCM_8,
        AES_256_GCM,
        ARIA_128_CBC,
        ARIA_128_GCM,
        ARIA_256_CBC,
        ARIA_256_GCM,
        CAMELLIA_128_CBC,
        CAMELLIA_128_GCM,
        CAMELLIA_256_CBC,
        CAMELLIA_256_GCM,
        CHACHA20_POLY1305,
        DES40_CBC,
        DES_CBC,
        DES_CBC_40,
        IDEA_CBC,
        KUZNYECHIK_CTR,
        KUZNYECHIK_MGM_L,
        KUZNYECHIK_MGM_S,
        MAGMA_CTR,
        MAGMA_MGM_L,
        MAGMA_MGM_S,
        NULL,
        RC2_CBC_40,
        RC4_128,
        RC4_40,
        SEED_CBC,
        SM4_CCM,
        SM4_GCM,
        _28147_CNT,
        _3DES_EDE_CBC
    }

    public enum Hash {
        GOSTR341112,
        MD5,
        NULL,
        SHA,
        SHA256,
        SHA384,
        SM3
    }
}
