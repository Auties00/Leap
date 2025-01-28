package it.auties.leap.tls.cipher;

public record TlsCipherIV(int fixed, int dynamic) {
    public int total() {
        return fixed + dynamic;
    }
}
