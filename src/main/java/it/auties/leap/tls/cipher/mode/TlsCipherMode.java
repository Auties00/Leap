package it.auties.leap.tls.cipher.mode;

import it.auties.leap.tls.cipher.TlsCipherIV;
import it.auties.leap.tls.cipher.engine.TlsCipherEngine;
import it.auties.leap.tls.cipher.mode.implementation.*;
import it.auties.leap.tls.exception.TlsException;
import it.auties.leap.tls.hash.TlsExchangeAuthenticator;
import it.auties.leap.tls.hash.TlsHmac;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;

public sealed abstract class TlsCipherMode {
    public static TlsCipherMode poly1305(TlsVersion version, TlsExchangeAuthenticator authenticator, TlsCipherEngine engine, byte[] fixedIv) {
        return new Poly1305Mode(version, authenticator, engine, fixedIv);
    }

    public static TlsCipherMode ctr(TlsVersion version, TlsExchangeAuthenticator authenticator, TlsCipherEngine engine, byte[] fixedIv) {
        return new CTRMode(version, authenticator, engine, fixedIv);
    }

    public static TlsCipherMode gcm(TlsVersion version, TlsExchangeAuthenticator authenticator, TlsCipherEngine engine, byte[] fixedIv) {
        return new GCMMode(version, authenticator, engine, fixedIv);
    }

    public static TlsCipherMode cbc(TlsVersion version, TlsExchangeAuthenticator authenticator, TlsCipherEngine engine, byte[] fixedIv) {
        return new CBCMode(version, authenticator, engine, fixedIv);
    }

    public static TlsCipherMode cbcExport(TlsVersion version, TlsExchangeAuthenticator authenticator, TlsCipherEngine engine, byte[] fixedIv) {
        return new CBCMode(version, authenticator, engine, fixedIv);
    }

    public static TlsCipherMode ccm(TlsVersion version, TlsExchangeAuthenticator authenticator, TlsCipherEngine engine, byte[] fixedIv) {
        return new CCMMode(version, authenticator, engine, fixedIv);
    }

    public static TlsCipherMode ccm8(TlsVersion version, TlsExchangeAuthenticator authenticator, TlsCipherEngine engine, byte[] fixedIv) {
        return new CCMMode(version, authenticator, engine, fixedIv);
    }

    public static TlsCipherMode none() {
        return NoneMode.instance();
    }

    public static TlsCipherMode mgmLight(TlsVersion version, TlsExchangeAuthenticator authenticator, TlsCipherEngine engine, byte[] fixedIv) {
        throw new UnsupportedOperationException();
    }

    public static TlsCipherMode mgmStrong(TlsVersion version, TlsExchangeAuthenticator authenticator, TlsCipherEngine engine, byte[] fixedIv) {
        throw new UnsupportedOperationException();
    }

    protected TlsVersion version;
    protected TlsExchangeAuthenticator authenticator;
    protected byte[] fixedIv;

    protected TlsCipherMode(TlsVersion version, TlsExchangeAuthenticator authenticator, byte[] fixedIv) {
        this.version = version;
        this.authenticator = authenticator;
        this.fixedIv = fixedIv;
    }
    
    public abstract void update(byte contentType, ByteBuffer input, ByteBuffer output, byte[] sequence);

    public abstract void doFinal(byte contentType, ByteBuffer input, ByteBuffer output);

    public abstract void reset();

    public abstract TlsCipherIV ivLength();

    public abstract int tagLength();

    protected void addMac(ByteBuffer destination, byte contentId) {
        if(authenticator.hmac().isEmpty()) {
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
        var hmac = authenticator.hmac()
                .orElse(null);
        if(hmac == null) {
            authenticator.increaseSequenceNumber();
            return;
        }

        var tagLen = hmac.length();
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
        var hmac = authenticator.hmac()
                .orElse(null);
        if(hmac == null) {
            authenticator.increaseSequenceNumber();
            return;
        }

        var tagLen = hmac.length();
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
        var remainingLen = calculateRemainingLen(hmac, cipheredLength, contentLen) + hmac.length();
        var temporary = ByteBuffer.allocate(remainingLen);
        checkMacTags(tagLen, contentType, temporary, sequence, true);
    }

    protected boolean checkMacTags(int tagLen, byte contentType, ByteBuffer bb, byte[] sequence, boolean isSimulated) {
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

    protected int calculateRemainingLen(TlsHmac type, int fullLen, int usedLen) {
        var blockLen = type.blockLength();
        var minimalPaddingLen = type.minimalPaddingLength();
        fullLen += 13 - (blockLen - minimalPaddingLen);
        usedLen += 13 - (blockLen - minimalPaddingLen);
        return 0x01 + (int) (Math.ceil(fullLen / (1.0d * blockLen)) -
                Math.ceil(usedLen / (1.0d * blockLen))) * blockLen;
    }

    public abstract non-sealed static class Block extends TlsCipherMode {
        protected TlsCipherEngine.Block engine;

        protected Block(TlsVersion version, TlsExchangeAuthenticator authenticator, TlsCipherEngine engine, byte[] fixedIv) {
            super(version, authenticator, fixedIv);
            if(!(engine instanceof TlsCipherEngine.Block blockEngine)) {
                throw new IllegalArgumentException();
            }

            this.engine = blockEngine;
        }

        @Override
        public TlsCipherIV ivLength() {
            var blockLength = blockLength();
            return new TlsCipherIV(blockLength, blockLength - fixedIv.length);
        }

        public int blockLength() {
            return engine.blockLength();
        }
    }

    public abstract non-sealed static class Stream extends TlsCipherMode {
        protected TlsCipherEngine.Stream engine;

        protected Stream(TlsVersion version, TlsExchangeAuthenticator authenticator, TlsCipherEngine engine, byte[] fixedIv) {
            super(version, authenticator, fixedIv);
            if(!(engine instanceof TlsCipherEngine.Stream blockEngine)) {
                throw new IllegalArgumentException();
            }

            this.engine = blockEngine;
        }

        @Override
        public TlsCipherIV ivLength() {
            return new TlsCipherIV(fixedIv.length, 0);
        }
    }
}
