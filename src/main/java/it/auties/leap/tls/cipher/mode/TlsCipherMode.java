package it.auties.leap.tls.cipher.mode;

import it.auties.leap.tls.cipher.engine.TlsCipherEngine;
import it.auties.leap.tls.cipher.mode.implementation.*;
import it.auties.leap.tls.exception.TlsException;
import it.auties.leap.tls.mac.TlsExchangeMac;
import it.auties.leap.tls.mac.TlsHmac;

import java.nio.ByteBuffer;

public sealed abstract class TlsCipherMode {
    public static TlsCipherMode poly1305(TlsCipherEngine engine) {
        return new Poly1305Mode(engine);
    }

    public static TlsCipherMode ctr(TlsCipherEngine engine) {
        return new CTRMode(engine);
    }

    public static TlsCipherMode gcm(TlsCipherEngine engine) {
        return new GCMMode(engine);
    }

    public static TlsCipherMode cbc(TlsCipherEngine engine) {
        return new CBCMode(engine);
    }

    public static TlsCipherMode cbcExport(TlsCipherEngine engine) {
        return new CBCMode(engine);
    }

    public static TlsCipherMode ccm(TlsCipherEngine engine) {
        return new CCMMode(engine);
    }

    public static TlsCipherMode ccm8(TlsCipherEngine engine) {
        return new CCMMode(engine);
    }

    public static TlsCipherMode none(TlsCipherEngine engine) {
        return NoneMode.instance();
    }

    public static TlsCipherMode mgmLight(TlsCipherEngine engine) {
        throw new UnsupportedOperationException();
    }

    public static TlsCipherMode mgmStrong(TlsCipherEngine engine) {
        throw new UnsupportedOperationException();
    }

    protected final TlsCipherEngine engine;
    protected TlsExchangeMac authenticator;
    protected byte[] fixedIv;
    protected boolean initialized;

    protected TlsCipherMode(TlsCipherEngine engine) {
        this.engine = engine;
    }

    @SuppressWarnings("unused")
    public void init(boolean forEncryption, byte[] key, byte[] fixedIv, TlsExchangeMac authenticator) {
        if(engine != null && engine.isInitialized()) {
            throw new TlsException("Engine already initialized");
        }

        if(initialized) {
            throw new TlsException("Engine mode is already initialized");
        }
        
        this.authenticator = authenticator;
        this.fixedIv = fixedIv;
        this.initialized = true;
    }

    public abstract void cipher(byte contentType, ByteBuffer input, ByteBuffer output, byte[] sequence);

    public abstract TlsCipherEngine engine();

    public abstract TlsCipherIV ivLength();

    public abstract int tagLength();

    public boolean isAEAD() {
        return tagLength() != 0;
    }

    public boolean isInitialized() {
        return initialized;
    }

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
        protected Block(TlsCipherEngine engine) {
            if(engine != null && !(engine instanceof TlsCipherEngine.Block)) {
                throw new TlsException("Expected block engine");
            }
            super(engine);
        }

        @Override
        public TlsCipherEngine.Block engine() {
            return (TlsCipherEngine.Block) engine;
        }
    }

    public abstract non-sealed static class Stream extends TlsCipherMode {
        protected Stream(TlsCipherEngine engine) {
            if(engine != null && !(engine instanceof TlsCipherEngine.Stream)) {
                throw new TlsException("Expected stream engine");
            }
            super(engine);
        }

        @Override
        public TlsCipherEngine.Stream engine() {
            return (TlsCipherEngine.Stream) engine;
        }
    }
}
