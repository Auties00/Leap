package it.auties.leap.tls.cipher.mode.implementation;

import it.auties.leap.tls.cipher.engine.TlsCipherEngine;
import it.auties.leap.tls.cipher.engine.implementation.KuznyechikEngine;
import it.auties.leap.tls.cipher.engine.implementation.MagmaEngine;
import it.auties.leap.tls.cipher.mode.TlsCipherMode;
import it.auties.leap.tls.cipher.mode.TlsCipherModeFactory;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.exception.TlsException;
import it.auties.leap.tls.mac.TlsExchangeMac;
import it.auties.leap.tls.message.TlsMessage;
import it.auties.leap.tls.message.TlsMessageMetadata;

import java.nio.ByteBuffer;

public final class MGMStrongMode extends TlsCipherMode.Block {
    private static final TlsCipherModeFactory FACTORY = MGMStrongMode::new;

    private MGMStrongMode(TlsCipherEngine engine) {
        if(!(engine instanceof KuznyechikEngine) && !(engine instanceof MagmaEngine)) {
            throw new TlsException("MGM_S mode is supported only by Kuznyechik and Magma engines");
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
    public ByteBuffer decrypt(TlsContext context, TlsMessageMetadata metadata, ByteBuffer input) {
        throw new UnsupportedOperationException();
    }

    @Override
    public int ivLength() {
        return engine().blockLength();
    }

    @Override
    public int fixedIvLength() {
        return engine().blockLength() - fixedIv.length;
    }

    @Override
    public int tagLength() {
        return engine().blockLength();
    }
}
