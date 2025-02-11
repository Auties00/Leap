package it.auties.leap.tls.cipher.mode;

import it.auties.leap.tls.cipher.TlsCipherIV;
import it.auties.leap.tls.cipher.engine.TlsCipherEngine;
import it.auties.leap.tls.cipher.mode.implementation.*;
import it.auties.leap.tls.exception.TlsException;
import it.auties.leap.tls.cipher.auth.TlsExchangeAuthenticator;
import it.auties.leap.tls.hash.TlsHmac;

import java.nio.ByteBuffer;

public sealed abstract class TlsCipherMode {
    public static TlsCipherMode poly1305() {
        return new Poly1305Mode();
    }

    public static TlsCipherMode ctr() {
        return new CTRMode();
    }

    public static TlsCipherMode gcm() {
        return new GCMMode();
    }

    public static TlsCipherMode cbc() {
        return new CBCMode();
    }

    public static TlsCipherMode cbcExport() {
        return new CBCMode();
    }

    public static TlsCipherMode ccm() {
        return new CCMMode();
    }

    public static TlsCipherMode ccm8() {
        return new CCMMode();
    }

    public static TlsCipherMode none() {
        return NoneMode.instance();
    }

    public static TlsCipherMode mgmLight() {
        throw new UnsupportedOperationException();
    }

    public static TlsCipherMode mgmStrong() {
        throw new UnsupportedOperationException();
    }

    protected TlsExchangeAuthenticator authenticator;
    protected TlsCipherEngine engine;
    protected byte[] fixedIv;
    protected boolean initialized;

    public void init(TlsExchangeAuthenticator authenticator, TlsCipherEngine engine, byte[] fixedIv) {
        if(engine != null && !engine.isInitialized()) {
            throw new TlsException("Engine is not initialized");
        }

        if(initialized) {
            throw new TlsException("Engine mode is already initialized");
        }
        
        this.authenticator = authenticator;
        this.engine = engine;
        this.fixedIv = fixedIv;
        this.initialized = true;
    }

    public abstract void update(byte contentType, ByteBuffer input, ByteBuffer output, byte[] sequence);

    public abstract void doFinal(byte contentType, ByteBuffer input, ByteBuffer output);

    public abstract void reset();

    public abstract TlsCipherEngine engine();

    public abstract TlsCipherIV ivLength();

    public abstract int tagLength();

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
        @Override
        public void init(TlsExchangeAuthenticator authenticator, TlsCipherEngine engine, byte[] fixedIv) {
            if(engine != null && !(engine instanceof TlsCipherEngine.Block)) {
                throw new TlsException("Expected block engine");
            }
            super.init(authenticator, engine, fixedIv);
        }

        @Override
        public TlsCipherEngine.Block engine() {
            return (TlsCipherEngine.Block) engine;
        }
    }

    public abstract non-sealed static class Stream extends TlsCipherMode {
        @Override
        public void init(TlsExchangeAuthenticator authenticator, TlsCipherEngine engine, byte[] fixedIv) {
            if(engine != null && !(engine instanceof TlsCipherEngine.Stream)) {
                throw new TlsException("Expected stream engine");
            }
            super.init(authenticator, engine, fixedIv);
        }

        @Override
        public TlsCipherEngine.Stream engine() {
            return (TlsCipherEngine.Stream) engine;
        }
    }
}
