package it.auties.leap.tls.cipher.mode.implementation;

import it.auties.leap.tls.cipher.engine.TlsCipherEngine;
import it.auties.leap.tls.cipher.engine.implementation.MagmaEngine;
import it.auties.leap.tls.cipher.mode.TlsCipherIV;
import it.auties.leap.tls.cipher.mode.TlsCipherMode;
import it.auties.leap.tls.cipher.mode.TlsCipherModeFactory;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.exception.TlsException;
import it.auties.leap.tls.mac.TlsExchangeMac;
import it.auties.leap.tls.message.TlsMessage;
import it.auties.leap.tls.message.TlsMessageMetadata;

import java.nio.ByteBuffer;

public final class CTRMode extends TlsCipherMode.Block {
    private static final TlsCipherModeFactory FACTORY = CNTImitMode::new;

    public CTRMode(TlsCipherEngine engine) {
        if(!(engine instanceof MagmaEngine)) {
            throw new TlsException("CTR mode is supported only by Magma engines");
        }
        super(engine);
    }

    public static TlsCipherModeFactory factory() {
        return FACTORY;
    }

    @Override
    public void init(boolean forEncryption, byte[] key, byte[] fixedIv, TlsExchangeMac authenticator) {
        super.init(forEncryption, key, fixedIv, authenticator);
    }

    @Override
    public void encrypt(TlsContext context, TlsMessage message, ByteBuffer output) {
        throw new UnsupportedOperationException();
    }

    @Override
    public TlsMessage decrypt(TlsContext context, TlsMessageMetadata metadata, ByteBuffer input) {
        throw new UnsupportedOperationException();
    }

    @Override
    public TlsCipherIV ivLength() {
        return new TlsCipherIV(4, 4);
    }

    @Override
    public int tagLength() {
        return 0;
    }
}