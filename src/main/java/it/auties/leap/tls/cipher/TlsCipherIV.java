package it.auties.leap.tls.cipher;

public record TlsCipherIV(int fixed, int dynamic) {
    private static final TlsCipherIV NONE = new TlsCipherIV(0, 0);

    public static TlsCipherIV none() {
        return NONE;
    }

    public int total() {
        return fixed + dynamic;
    }
}
