package it.auties.leap.tls.srtp;

import it.auties.leap.tls.cipher.TlsCipherSuite;
import it.auties.leap.tls.cipher.auth.TlsAuthFactory;
import it.auties.leap.tls.cipher.engine.TlsCipherEngineFactory;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchangeFactory;
import it.auties.leap.tls.cipher.mode.TlsCipherFactory;
import it.auties.leap.tls.hash.TlsHashFactory;
import it.auties.leap.tls.version.TlsVersion;

import java.util.List;

public final class TlsSrtpCipherSuite extends TlsCipherSuite {
    private static final TlsSrtpCipherSuite SRTP_AES_CM_128_HMAC_SHA1_80 = new TlsSrtpCipherSuite(0x0001, TlsCipherEngineFactory.aes128(), TlsCipherFactory.cm(), TlsKeyExchangeFactory.contextual(), TlsAuthFactory.hmacSha1(), TlsHashFactory.none(), List.of(TlsVersion.DTLS10, TlsVersion.DTLS12), true);
    private static final TlsSrtpCipherSuite SRTP_AES_CM_128_HMAC_SHA1_32 = new TlsSrtpCipherSuite(0x0002, TlsCipherEngineFactory.aes128(), TlsCipherFactory.cm(), TlsKeyExchangeFactory.contextual(), TlsAuthFactory.hmacSha1(), TlsHashFactory.none(), List.of(TlsVersion.DTLS10, TlsVersion.DTLS12), true);
    private static final TlsSrtpCipherSuite SRTP_F8_128_HMAC_SHA1_80 = new TlsSrtpCipherSuite(0x0003, TlsCipherEngineFactory.aes128(), TlsCipherFactory.f8(), TlsKeyExchangeFactory.contextual(), TlsAuthFactory.hmacSha1(), TlsHashFactory.none(), List.of(TlsVersion.DTLS10, TlsVersion.DTLS12), true);
    private static final TlsSrtpCipherSuite SRTP_F8_128_HMAC_SHA1_32 = new TlsSrtpCipherSuite(0x0004, TlsCipherEngineFactory.aes128(), TlsCipherFactory.f8(), TlsKeyExchangeFactory.contextual(), TlsAuthFactory.hmacSha1(), TlsHashFactory.none(), List.of(TlsVersion.DTLS10, TlsVersion.DTLS12), true);
    private static final TlsSrtpCipherSuite SRTP_NULL_HMAC_SHA1_80 = new TlsSrtpCipherSuite(0x0005, TlsCipherEngineFactory.none(), TlsCipherFactory.none(), TlsKeyExchangeFactory.contextual(), TlsAuthFactory.hmacSha1(), TlsHashFactory.none(), List.of(TlsVersion.DTLS10, TlsVersion.DTLS12), false);
    private static final TlsSrtpCipherSuite SRTP_NULL_HMAC_SHA1_32 = new TlsSrtpCipherSuite(0x0006, TlsCipherEngineFactory.none(), TlsCipherFactory.none(), TlsKeyExchangeFactory.contextual(), TlsAuthFactory.hmacSha1(), TlsHashFactory.none(), List.of(TlsVersion.DTLS10, TlsVersion.DTLS12), false);
    private static final TlsSrtpCipherSuite SRTP_AEAD_AES_128_GCM = new TlsSrtpCipherSuite(0x0007, TlsCipherEngineFactory.aes128(), TlsCipherFactory.gcm(), TlsKeyExchangeFactory.contextual(), TlsAuthFactory.contextual(), TlsHashFactory.none(), List.of(TlsVersion.DTLS13), true);
    private static final TlsSrtpCipherSuite SRTP_AEAD_AES_256_GCM = new TlsSrtpCipherSuite(0x0008, TlsCipherEngineFactory.aes256(), TlsCipherFactory.gcm(), TlsKeyExchangeFactory.contextual(), TlsAuthFactory.contextual(), TlsHashFactory.none(), List.of(TlsVersion.DTLS13), true);
    private static final TlsSrtpCipherSuite SRTP_AES_256_CM_HMAC_SHA1_80 = new TlsSrtpCipherSuite(0x0009, TlsCipherEngineFactory.aes256(), TlsCipherFactory.cm(), TlsKeyExchangeFactory.contextual(), TlsAuthFactory.hmacSha1(), TlsHashFactory.none(), List.of(TlsVersion.DTLS10, TlsVersion.DTLS12), true);
    private static final TlsSrtpCipherSuite SRTP_AES_256_CM_HMAC_SHA1_32 = new TlsSrtpCipherSuite(0x000A, TlsCipherEngineFactory.aes256(), TlsCipherFactory.cm(), TlsKeyExchangeFactory.contextual(), TlsAuthFactory.hmacSha1(), TlsHashFactory.none(), List.of(TlsVersion.DTLS10, TlsVersion.DTLS12), true);
    private static final TlsSrtpCipherSuite SRTP_AES_192_CM_HMAC_SHA1_80 = new TlsSrtpCipherSuite(0x000B, TlsCipherEngineFactory.aes192(), TlsCipherFactory.cm(), TlsKeyExchangeFactory.contextual(), TlsAuthFactory.hmacSha1(), TlsHashFactory.none(), List.of(TlsVersion.DTLS10, TlsVersion.DTLS12), true);
    private static final TlsSrtpCipherSuite SRTP_AES_192_CM_HMAC_SHA1_32 = new TlsSrtpCipherSuite(0x000C, TlsCipherEngineFactory.aes192(), TlsCipherFactory.cm(), TlsKeyExchangeFactory.contextual(), TlsAuthFactory.hmacSha1(), TlsHashFactory.none(), List.of(TlsVersion.DTLS10, TlsVersion.DTLS12), true);

    private TlsSrtpCipherSuite(int id, TlsCipherEngineFactory cipherEngine, TlsCipherFactory cipherMode, TlsKeyExchangeFactory keyExchange, TlsAuthFactory auth, TlsHashFactory hash, List<TlsVersion> versions, boolean secure) {
        super(id, cipherEngine, cipherMode, keyExchange, auth, hash, versions, secure);
    }

    public static TlsSrtpCipherSuite aesCm128HmacSha180() { return SRTP_AES_CM_128_HMAC_SHA1_80; }

    public static TlsSrtpCipherSuite aesCm128HmacSha132() { return SRTP_AES_CM_128_HMAC_SHA1_32; }

    public static TlsSrtpCipherSuite f8128HmacSha180() { return SRTP_F8_128_HMAC_SHA1_80; }

    public static TlsSrtpCipherSuite f8128HmacSha132() { return SRTP_F8_128_HMAC_SHA1_32; }

    public static TlsSrtpCipherSuite nullHmacSha180() { return SRTP_NULL_HMAC_SHA1_80; }

    public static TlsSrtpCipherSuite nullHmacSha132() { return SRTP_NULL_HMAC_SHA1_32; }

    public static TlsSrtpCipherSuite aeadAes128Gcm() { return SRTP_AEAD_AES_128_GCM; }

    public static TlsSrtpCipherSuite aeadAes256Gcm() { return SRTP_AEAD_AES_256_GCM; }

    public static TlsSrtpCipherSuite aes256CmHmacSha180() { return SRTP_AES_256_CM_HMAC_SHA1_80; }

    public static TlsSrtpCipherSuite aes256CmHmacSha132() { return SRTP_AES_256_CM_HMAC_SHA1_32; }

    public static TlsSrtpCipherSuite aes192CmHmacSha180() { return SRTP_AES_192_CM_HMAC_SHA1_80; }

    public static TlsSrtpCipherSuite aes192CmHmacSha132() { return SRTP_AES_192_CM_HMAC_SHA1_32; }
}
