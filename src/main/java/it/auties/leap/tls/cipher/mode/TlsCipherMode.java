package it.auties.leap.tls.cipher.mode;

import it.auties.leap.tls.cipher.engine.TlsCipherEngine;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.cipher.exchange.TlsExchangeMac;
import it.auties.leap.tls.hash.TlsHmac;
import it.auties.leap.tls.message.TlsMessage;
import it.auties.leap.tls.message.TlsMessageMetadata;

import java.nio.ByteBuffer;
import java.util.Arrays;

public sealed abstract class TlsCipherMode {
    protected final TlsCipherEngine engine;
    protected TlsExchangeMac authenticator;
    protected byte[] fixedIv;

    protected TlsCipherMode(TlsCipherEngine engine, byte[] fixedIv, TlsExchangeMac authenticator) {
        this.engine = engine;
        this.authenticator = authenticator;
        this.fixedIv = fixedIv;
    }

    public abstract void encrypt(TlsContext context, TlsMessage message, ByteBuffer output);

    public abstract ByteBuffer decrypt(TlsContext context, TlsMessageMetadata metadata, ByteBuffer input);

    public abstract TlsCipherEngine engine();

    public abstract int ivLength();

    public abstract int fixedIvLength();

    public int dynamicIvLength() {
        return ivLength() - fixedIvLength();
    }

    public abstract int tagLength();

    public boolean aead() {
        return tagLength() != 0;
    }

    protected void addMac(ByteBuffer destination, byte contentId) {
        if(authenticator.hmac().isEmpty()) {
            authenticator.increaseSequenceNumber();
            return;
        }

        var hmac = authenticator.createAuthenticationHmacBlock(contentId, destination, null, false)
                .orElseThrow(() -> new TlsAlert("Expected mac capabilities from an authenticator with an HMAC"));
        System.out.println("Using HMAC: " + Arrays.toString(hmac));
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
            throw new TlsAlert("bad record");
        }

        if (!checkMacTags(tagLen, contentType, bb, sequence, false)) {
            throw new TlsAlert("bad record MAC");
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
            throw new TlsAlert("bad record");
        }

        if (!checkMacTags(tagLen, contentType, bb, sequence, false)) {
            throw new TlsAlert("bad record MAC");
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
                .orElseThrow(() -> new TlsAlert("Expected mac capabilities from an authenticator with an HMAC"));
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
        protected Block(TlsCipherEngine engine, byte[] fixedIv, TlsExchangeMac authenticator) {
            if(engine != null && !(engine instanceof TlsCipherEngine.Block)) {
                throw new TlsAlert("Expected block engine");
            }

            super(engine, fixedIv, authenticator);
        }

        @Override
        public TlsCipherEngine.Block engine() {
            return (TlsCipherEngine.Block) engine;
        }
    }

    public abstract non-sealed static class Stream extends TlsCipherMode {
        protected Stream(TlsCipherEngine engine, byte[] fixedIv, TlsExchangeMac authenticator) {
            if(engine != null && !(engine instanceof TlsCipherEngine.Stream)) {
                throw new TlsAlert("Expected stream engine");
            }
            super(engine, fixedIv, authenticator);
        }

        @Override
        public TlsCipherEngine.Stream engine() {
            return (TlsCipherEngine.Stream) engine;
        }
    }
}
