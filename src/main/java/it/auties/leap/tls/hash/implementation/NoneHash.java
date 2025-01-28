package it.auties.leap.tls.hash.implementation;

import it.auties.leap.tls.hash.TlsHash;
import it.auties.leap.tls.hash.TlsHashFactory;

import java.nio.ByteBuffer;

public final class NoneHash implements TlsHash {
    private static final NoneHash INSTANCE = new NoneHash();
    private static final TlsHashFactory FACTORY = NoneHash::instance;
    private static final byte[] EMPTY_BUFFER = new byte[0];

    private NoneHash() {

    }

    public static NoneHash instance() {
        return INSTANCE;
    }

    public static TlsHashFactory factory() {
        return FACTORY;
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
    public int length() {
        return 0;
    }

    @Override
    public int blockLength() {
        return 0;
    }

    @Override
    public TlsHash duplicate() {
        return INSTANCE;
    }
}
