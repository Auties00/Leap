package it.auties.leap.tls.cipher.wrapper;

import it.auties.leap.tls.cipher.TlsCipher;
import it.auties.leap.tls.exception.TlsException;
import it.auties.leap.tls.config.TlsVersion;
import it.auties.leap.tls.hash.TlsExchangeAuthenticator;
import it.auties.leap.tls.key.TlsSessionKeys;
import it.auties.leap.tls.config.TlsMode;
import it.auties.leap.tls.message.TlsMessage.ContentType;

import java.nio.ByteBuffer;

public abstract sealed class TlsCipherWrapper permits CBCWrapper, CCMWrapper, CTRWrapper, ChaCha20Poly1305Wrapper, GCMWrapper, MGMWrapper, NULLWrapper {
    protected final TlsVersion version;
    protected final TlsCipher cipher;
    protected final TlsExchangeAuthenticator authenticator;
    protected final TlsSessionKeys sessionKeys;
    protected final TlsMode mode;
    protected TlsCipherWrapper(TlsVersion version, TlsCipher cipher, TlsExchangeAuthenticator authenticator, TlsSessionKeys sessionKeys, TlsMode mode) {
        this.version = version;
        this.cipher = cipher;
        this.authenticator = authenticator;
        this.sessionKeys = sessionKeys;
        this.mode = mode;
    }

    public static TlsCipherWrapper of(
            TlsVersion version,
            TlsCipher cipher,
            TlsExchangeAuthenticator authenticator,
            TlsSessionKeys sessionKeys,
            TlsMode mode
    ) {
        return switch (cipher.type().mode()) {
            case NULL -> new NULLWrapper(authenticator);
            case CTR -> new CTRWrapper(version, cipher, authenticator, sessionKeys, mode);
            case CHACHA20_POLY1305 -> new ChaCha20Poly1305Wrapper(version, cipher, authenticator, sessionKeys, mode);
            case GCM -> new GCMWrapper(version, cipher, authenticator, sessionKeys, mode);
            case CBC -> new CBCWrapper(version, cipher, authenticator, sessionKeys, mode, false);
            case CBC_40 -> new CBCWrapper(version, cipher, authenticator, sessionKeys, mode, true);
            case CCM -> new CCMWrapper(version, cipher, authenticator, sessionKeys, mode, false);
            case CCM_8 -> new CCMWrapper(version, cipher, authenticator, sessionKeys, mode, true);
            case MGM_S -> new MGMWrapper(version, cipher, authenticator, sessionKeys, mode, false);
            case MGM_L -> new MGMWrapper(version, cipher, authenticator, sessionKeys, mode, true);
        };
    }

    public abstract void encrypt(ContentType contentType, ByteBuffer input, ByteBuffer output);
    public abstract void decrypt(ContentType contentType, ByteBuffer input, ByteBuffer output, byte[] sequence);
    public abstract int nonceLength();

    protected void addMac(ByteBuffer destination, byte contentId) {
        if(authenticator.hmacType().isEmpty()) {
            authenticator.increaseSequenceNumber();
            return;
        }

        var hmac = authenticator.createAuthenticationHmacBlock(contentId, destination, null, false)
                .orElseThrow(() -> new TlsException("Expected mac capabilities from an authenticator with an HMAC"));
        var hmacPosition = destination.limit();
        destination.limit(hmacPosition + hmac.length);
        destination.put(hmacPosition, hmac);
    }

    protected void checkStreamMac(ByteBuffer bb, byte contentType, byte[] sequence) {
        var hmacType = authenticator.hmacType()
                .orElse(null);
        if(hmacType == null) {
            authenticator.increaseSequenceNumber();
            return;
        }

        var tagLen = hmacType.length();
        if (tagLen == 0) {
            return;
        }

        var contentLen = bb.remaining() - tagLen;
        if (contentLen < 0) {
            throw new TlsException("bad record");
        }

        if (!checkMacTags(tagLen, contentType, bb, sequence, false)) {
            throw new TlsException("bad record MAC");
        }
    }

    protected void checkCbcMac(ByteBuffer bb, byte contentType, byte[] sequence) {
        var hmacType = authenticator.hmacType()
                .orElse(null);
        if(hmacType == null) {
            authenticator.increaseSequenceNumber();
            return;
        }

        var tagLen = hmacType.length();
        if (tagLen == 0) {
            return;
        }

        var contentLen = bb.remaining() - tagLen;
        if (contentLen < 0) {
            throw new TlsException("bad record");
        }

        if (!checkMacTags(tagLen, contentType, bb, sequence, false)) {
            throw new TlsException("bad record MAC");
        }

        var cipheredLength = bb.remaining();
        var remainingLen = calculateRemainingLen(hmacType, cipheredLength, contentLen) + hmacType.length();
        var temporary = ByteBuffer.allocate(remainingLen);
        checkMacTags(tagLen, contentType, temporary, sequence, true);
    }

    private boolean checkMacTags(int tagLen, byte contentType, ByteBuffer bb, byte[] sequence, boolean isSimulated) {
        var position = bb.position();
        var lim = bb.limit();
        var macOffset = lim - tagLen;
        bb.limit(macOffset);
        var hash = authenticator.createAuthenticationHmacBlock(contentType, bb, sequence, isSimulated)
                .orElseThrow(() -> new TlsException("Expected mac capabilities from an authenticator with an HMAC"));
        bb.position(macOffset);
        bb.limit(lim);
        try {
            for (var t : hash) {
                if (bb.get() != t) {
                    return false;
                }
            }
            return true;
        } finally {
            bb.position(position);
            bb.limit(macOffset);
        }
    }

    private int calculateRemainingLen(TlsCipher.Hmac type, int fullLen, int usedLen) {
        var blockLen = type.toHash().blockLength();
        var minimalPaddingLen = type.minimalPaddingLength();
        fullLen += 13 - (blockLen - minimalPaddingLen);
        usedLen += 13 - (blockLen - minimalPaddingLen);
        return 0x01 + (int) (Math.ceil(fullLen / (1.0d * blockLen)) -
                Math.ceil(usedLen / (1.0d * blockLen))) * blockLen;
    }
}
