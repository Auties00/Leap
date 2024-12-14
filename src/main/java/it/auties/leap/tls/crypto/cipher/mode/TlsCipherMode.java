package it.auties.leap.tls.crypto.cipher.mode;

import it.auties.leap.tls.TlsCipher;
import it.auties.leap.tls.crypto.cipher.engine.TlsCipherEngine;

import java.nio.ByteBuffer;

public sealed interface TlsCipherMode permits TlsCipherMode.Stream, TlsCipherMode.Block, TlsCipherMode.AEAD {
    static TlsCipherMode of(
            TlsCipher cipher,
            TlsCipherEngine engine,
            byte[] iv
    ) {
        return switch (cipher.type().mode()) {
            case NULL -> throw new InternalError("Unexpected call with NULL cipher engine");
            case CHACHA20_POLY1305 -> new ChaCha20Poly1305Mode(engine, iv);
            case CTR -> new CTRMode(engine, iv);
            case GCM -> new GCMMode(engine, iv);
            case CBC -> new CBCMode(engine, iv);
            case CBC_40 -> new CBCMode(engine, iv);
            case CCM -> new CCMMode(engine, iv);
            case CCM_8 -> new CCMMode(engine, iv);
            case MGM_L -> new MGMMode(engine, iv);
            case MGM_S -> new MGMMode(engine, iv);
        };
    }

    void update(ByteBuffer input, ByteBuffer output, boolean last);
    void reset();

    sealed interface Stream extends TlsCipherMode permits ChaCha20Poly1305Mode {

    }

    sealed interface Block extends TlsCipherMode permits CBCMode, CCMMode, CTRMode, GCMMode {
        int blockSize();
    }

    sealed interface AEAD extends TlsCipherMode permits CCMMode, ChaCha20Poly1305Mode, GCMMode {

    }
}