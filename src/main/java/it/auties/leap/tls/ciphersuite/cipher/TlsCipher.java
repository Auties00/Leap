package it.auties.leap.tls.ciphersuite.cipher;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
import it.auties.leap.tls.ciphersuite.engine.TlsCipherEngine;
import it.auties.leap.tls.ciphersuite.exchange.TlsExchangeMac;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.hash.TlsHmac;
import it.auties.leap.tls.message.TlsMessageMetadata;

import java.nio.ByteBuffer;
import java.util.Arrays;

public sealed abstract class TlsCipher {
    protected final TlsCipherEngine engine;
    protected final TlsExchangeMac authenticator;
    protected final byte[] fixedIv;
    protected boolean enabled;

    protected TlsCipher(TlsCipherEngine engine, byte[] fixedIv, TlsExchangeMac authenticator) {
        /*
        FIXME: In (d)tls1.3, the length of the IV report by the engines is not correct currently
        if(fixedIv == null || fixedIv.length != fixedIvLength()) {
            throw new TlsAlert("Unexpected IV length", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
        }
         */

        this.engine = engine;
        this.authenticator = authenticator;
        this.fixedIv = fixedIv;
        this.enabled = false;
    }

    public abstract void encrypt(byte contentType, ByteBuffer input, ByteBuffer output);

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

    public boolean enabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    protected void addMac(ByteBuffer destination, byte contentId) {
        if(authenticator.hmac().isEmpty()) {
            authenticator.increaseSequenceNumber();
            return;
        }

        var hmac = authenticator.createAuthenticationHmacBlock(contentId, destination, null, false)
                .orElseThrow(() -> new TlsAlert("Expected mac capabilities from an authenticator with an HMAC", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR));
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
            throw new TlsAlert("bad record", TlsAlertLevel.FATAL, TlsAlertType.BAD_RECORD_MAC);
        }

        if (!checkMacTags(tagLen, contentType, bb, sequence, false)) {
            throw new TlsAlert("bad record MAC", TlsAlertLevel.FATAL, TlsAlertType.BAD_RECORD_MAC);
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
            throw new TlsAlert("bad record", TlsAlertLevel.FATAL, TlsAlertType.BAD_RECORD_MAC);
        }

        if (!checkMacTags(tagLen, contentType, bb, sequence, false)) {
            throw new TlsAlert("bad record MAC", TlsAlertLevel.FATAL, TlsAlertType.BAD_RECORD_MAC);
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
                .orElseThrow(() -> new TlsAlert("Expected mac capabilities from an authenticator with an HMAC", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR));
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

    public abstract non-sealed static class Block extends TlsCipher {
        protected Block(TlsCipherEngine engine, byte[] fixedIv, TlsExchangeMac authenticator) {
            if(engine != null && !(engine instanceof TlsCipherEngine.Block)) {
                throw new TlsAlert("Expected block engine", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
            }

            super(engine, fixedIv, authenticator);
        }

        @Override
        public TlsCipherEngine.Block engine() {
            return (TlsCipherEngine.Block) engine;
        }
    }

    public abstract non-sealed static class Stream extends TlsCipher {
        protected Stream(TlsCipherEngine engine, byte[] fixedIv, TlsExchangeMac authenticator) {
            if(engine != null && !(engine instanceof TlsCipherEngine.Stream)) {
                throw new TlsAlert("Expected stream engine", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
            }
            super(engine, fixedIv, authenticator);
        }

        @Override
        public TlsCipherEngine.Stream engine() {
            return (TlsCipherEngine.Stream) engine;
        }
    }
}
