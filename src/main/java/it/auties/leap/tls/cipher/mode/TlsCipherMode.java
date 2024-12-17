package it.auties.leap.tls.cipher.mode;

import it.auties.leap.tls.cipher.engine.TlsCipherEngine;

import java.nio.ByteBuffer;

public sealed interface TlsCipherMode {
    void update(ByteBuffer input, ByteBuffer output, boolean last);

    void reset();

    abstract non-sealed class Block implements TlsCipherMode {
        protected final TlsCipherEngine.Block engine;
        protected final byte[] iv;

        protected Block(TlsCipherEngine.Block engine, byte[] iv) {
            this.engine = engine;
            this.iv = iv;
        }

        public abstract int blockSize();
    }

    abstract non-sealed class Stream implements TlsCipherMode {
        protected final TlsCipherEngine.Stream engine;
        protected final byte[] iv;

        protected Stream(TlsCipherEngine.Stream engine, byte[] iv) {
            this.engine = engine;
            this.iv = iv;
        }
    }

    interface AEAD {

    }
}
