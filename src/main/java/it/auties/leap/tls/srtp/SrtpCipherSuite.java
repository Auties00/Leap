package it.auties.leap.tls.srtp;

import it.auties.leap.tls.ciphersuite.TlsCipherSuite;
import it.auties.leap.tls.ciphersuite.auth.TlsAuth;
import it.auties.leap.tls.ciphersuite.engine.TlsCipherEngineFactory;
import it.auties.leap.tls.ciphersuite.exchange.TlsKeyExchangeFactory;
import it.auties.leap.tls.ciphersuite.cipher.TlsCipherFactory;
import it.auties.leap.tls.hash.TlsHashFactory;
import it.auties.leap.tls.version.TlsVersion;
import it.auties.leap.tls.version.TlsVersions;

public final class SrtpCipherSuite extends TlsCipherSuite {
    private static final SrtpCipherSuite SRTP_AES_CM_128_HMAC_SHA1_80 = new SrtpCipherSuite(0x0001, TlsCipherEngineFactory.aes128(), TlsCipherFactory.ctr(), null, TlsAuth.hmacSha1(), TlsHashFactory.none(), TlsVersions.of(TlsVersion.DTLS10));
    private static final SrtpCipherSuite SRTP_AES_CM_128_HMAC_SHA1_32 = new SrtpCipherSuite(0x0002, TlsCipherEngineFactory.aes128(), TlsCipherFactory.ctr(), null, TlsAuth.hmacSha1(), TlsHashFactory.none(), TlsVersions.of(TlsVersion.DTLS10));
    private static final SrtpCipherSuite SRTP_F8_128_HMAC_SHA1_80 = new SrtpCipherSuite(0x0003, TlsCipherEngineFactory.aes128(), TlsCipherFactory.f8(), null, TlsAuth.hmacSha1(), TlsHashFactory.none(), TlsVersions.of(TlsVersion.DTLS10));
    private static final SrtpCipherSuite SRTP_F8_128_HMAC_SHA1_32 = new SrtpCipherSuite(0x0004, TlsCipherEngineFactory.aes128(), TlsCipherFactory.f8(), null, TlsAuth.hmacSha1(), TlsHashFactory.none(), TlsVersions.of(TlsVersion.DTLS10));
    private static final SrtpCipherSuite SRTP_NULL_HMAC_SHA1_80 = new SrtpCipherSuite(0x0005, TlsCipherEngineFactory.none(), TlsCipherFactory.none(), null, TlsAuth.hmacSha1(), TlsHashFactory.none(), TlsVersions.of(TlsVersion.DTLS10));
    private static final SrtpCipherSuite SRTP_NULL_HMAC_SHA1_32 = new SrtpCipherSuite(0x0006, TlsCipherEngineFactory.none(), TlsCipherFactory.none(), null, TlsAuth.hmacSha1(), TlsHashFactory.none(), TlsVersions.of(TlsVersion.DTLS10));
    private static final SrtpCipherSuite SRTP_AEAD_AES_128_GCM = new SrtpCipherSuite(0x0007, TlsCipherEngineFactory.aes128(), TlsCipherFactory.gcm(), null, null, TlsHashFactory.none(), TlsVersions.of(TlsVersion.DTLS13));
    private static final SrtpCipherSuite SRTP_AEAD_AES_256_GCM = new SrtpCipherSuite(0x0008, TlsCipherEngineFactory.aes256(), TlsCipherFactory.gcm(), null, null, TlsHashFactory.none(), TlsVersions.of(TlsVersion.DTLS13));
    private static final SrtpCipherSuite SRTP_AES_256_CM_HMAC_SHA1_80 = new SrtpCipherSuite(0x0009, TlsCipherEngineFactory.aes256(), TlsCipherFactory.ctr(), null, TlsAuth.hmacSha1(), TlsHashFactory.none(), TlsVersions.of(TlsVersion.DTLS10));
    private static final SrtpCipherSuite SRTP_AES_256_CM_HMAC_SHA1_32 = new SrtpCipherSuite(0x000A, TlsCipherEngineFactory.aes256(), TlsCipherFactory.ctr(), null, TlsAuth.hmacSha1(), TlsHashFactory.none(), TlsVersions.of(TlsVersion.DTLS10));
    private static final SrtpCipherSuite SRTP_AES_192_CM_HMAC_SHA1_80 = new SrtpCipherSuite(0x000B, TlsCipherEngineFactory.aes192(), TlsCipherFactory.ctr(), null, TlsAuth.hmacSha1(), TlsHashFactory.none(), TlsVersions.of(TlsVersion.DTLS10));
    private static final SrtpCipherSuite SRTP_AES_192_CM_HMAC_SHA1_32 = new SrtpCipherSuite(0x000C, TlsCipherEngineFactory.aes192(), TlsCipherFactory.ctr(), null, TlsAuth.hmacSha1(), TlsHashFactory.none(), TlsVersions.of(TlsVersion.DTLS10));

    private SrtpCipherSuite(int id, TlsCipherEngineFactory cipherEngine, TlsCipherFactory cipherMode, TlsKeyExchangeFactory keyExchange, TlsAuth auth, TlsHashFactory hash, TlsVersions versions) {
        super(id, cipherEngine, cipherMode, keyExchange, auth, hash, versions);
    }

    public static SrtpCipherSuite aesCm128HmacSha180() { return SRTP_AES_CM_128_HMAC_SHA1_80; }

    public static SrtpCipherSuite aesCm128HmacSha132() { return SRTP_AES_CM_128_HMAC_SHA1_32; }

    public static SrtpCipherSuite f8128HmacSha180() { return SRTP_F8_128_HMAC_SHA1_80; }

    public static SrtpCipherSuite f8128HmacSha132() { return SRTP_F8_128_HMAC_SHA1_32; }

    public static SrtpCipherSuite nullHmacSha180() { return SRTP_NULL_HMAC_SHA1_80; }

    public static SrtpCipherSuite nullHmacSha132() { return SRTP_NULL_HMAC_SHA1_32; }

    public static SrtpCipherSuite aes128Gcm() { return SRTP_AEAD_AES_128_GCM; }

    public static SrtpCipherSuite aes256Gcm() { return SRTP_AEAD_AES_256_GCM; }

    public static SrtpCipherSuite aes256CmHmacSha180() { return SRTP_AES_256_CM_HMAC_SHA1_80; }

    public static SrtpCipherSuite aes256CmHmacSha132() { return SRTP_AES_256_CM_HMAC_SHA1_32; }

    public static SrtpCipherSuite aes192CmHmacSha180() { return SRTP_AES_192_CM_HMAC_SHA1_80; }

    public static SrtpCipherSuite aes192CmHmacSha132() { return SRTP_AES_192_CM_HMAC_SHA1_32; }
}
