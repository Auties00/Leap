package it.auties.leap.tls.hash.digest;

import it.auties.leap.tls.TlsHashType;
import it.auties.leap.tls.hash.TlsHash;

import java.nio.ByteBuffer;

public final class NULL extends TlsHash {
    private static final byte[] EMPTY_BUFFER = new byte[0];
    public static final NULL INSTANCE = new NULL();
    
    private NULL() {
        
    }
    

    @Override
    public void update(byte input) {
        
    }

    @Override
    public void update(byte[] input, int offset, int len) {

    }

    @Override
    public void update(ByteBuffer input) {

    }

    @Override
    public int digest(byte[] output, int offset, int length, boolean reset) {
        return 0;
    }

    @Override
    public byte[] digest(boolean reset) {
        return EMPTY_BUFFER;
    }

    @Override
    public void reset() {
        
    }

    @Override
    public TlsHashType type() {
        return TlsHashType.NULL;
    }
}
