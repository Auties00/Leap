package it.auties.leap.tls.version;

// TODO: When value types drop (maybe JDK 26?) make this a value type so we don't get any overhead
// It's not like this library will be ready soon lol, might as well design with future proofing in mind
public final class TlsVersions {
    private final TlsVersion low;
    private final TlsVersion high;

    private TlsVersions(TlsVersion low, TlsVersion high) {
        this.low = low;
        this.high = high;
    }

    public static TlsVersions range(TlsVersion low, TlsVersion high) {
        return new TlsVersions(low, high);
    }

    public static TlsVersions of(TlsVersion low) {
        return new TlsVersions(low, null);
    }

    public boolean accepts(TlsVersion version) {
        if(high == null) {
            return low == version;
        }else {
            return version.ordinal() >= low.ordinal()
                    && version.ordinal() <= high.ordinal();
        }
    }
}
