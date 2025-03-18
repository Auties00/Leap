package it.auties.leap.http.exchange.headers;

import java.util.*;
import java.util.function.BiConsumer;
import java.util.function.Function;

public sealed class HttpHeaders permits HttpMutableHeaders {
    private static final HttpHeaders EMPTY = new HttpHeaders();
    protected final Map<String, Object> backing;

    HttpHeaders() {
        this.backing = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
    }

    HttpHeaders(Map<String, Object> backing) {
        this.backing = backing;
    }

    public static HttpHeaders empty() {
        return EMPTY;
    }

    public static HttpHeaders newImmutableHeaders() {
        return new HttpHeaders();
    }

    public static HttpHeaders newImmutableHeaders(HttpHeaders headers) {
        var instance = new HttpHeaders();
        instance.backing.putAll(headers.backing);
        return instance;
    }

    public void forEach(BiConsumer<? super String, ? super Object> action) {
        backing.forEach(action);
    }

    public int size() {
        return backing.size();
    }

    public Optional<String> cacheControl() {
        return getAsString("Cache-Control");
    }

    public Optional<String> connection() {
        return getAsString("Connection");
    }

    public Optional<String> date() {
        return getAsString("Date");
    }

    public Optional<String> pragma() {
        return getAsString("Pragma");
    }

    public Optional<String> trailer() {
        return getAsString("Trailer");
    }

    public Optional<String> transferEncoding() {
        return getAsString("Transfer-Encoding");
    }

    public Optional<String> upgrade() {
        return getAsString("Upgrade");
    }

    public Optional<String> via() {
        return getAsString("Via");
    }

    public Optional<String> warning() {
        return getAsString("Warning");
    }
    
    public Optional<String> accept() {
        return getAsString("Accept");
    }

    public Optional<String> acceptCharset() {
        return getAsString("Accept-Charset");
    }

    public Optional<String> acceptEncoding() {
        return getAsString("Accept-Encoding");
    }

    public Optional<String> acceptLanguage() {
        return getAsString("Accept-Language");
    }

    public Optional<String> authorization() {
        return getAsString("Authorization");
    }

    public Optional<String> expect() {
        return getAsString("Expect");
    }

    public Optional<String> from() {
        return getAsString("From");
    }

    public Optional<String> host() {
        return getAsString("Host");
    }

    public Optional<String> ifMatch() {
        return getAsString("If-Match");
    }

    public Optional<String> ifModifiedSince() {
        return getAsString("If-Modified-Since");
    }

    public Optional<String> ifNoneMatch() {
        return getAsString("If-None-Match");
    }

    public Optional<String> ifRange() {
        return getAsString("If-Range");
    }

    public Optional<String> ifUnmodifiedSince() {
        return getAsString("If-Unmodified-Since");
    }

    public OptionalLong maxForwards() {
        return getAsLong("Max-Forwards");
    }

    public Optional<String> proxyAuthorization() {
        return getAsString("Proxy-Authorization");
    }

    public Optional<String> range() {
        return getAsString("Range");
    }

    public Optional<String> referer() {
        return getAsString("Referer");
    }

    public Optional<String> te() {
        return getAsString("TE");
    }

    public Optional<String> userAgent() {
        return getAsString("User-Agent");
    }

    public Optional<String> acceptRanges() {
        return getAsString("Accept-Ranges");
    }

    public OptionalLong age() {
        return getAsLong("Age");
    }

    public Optional<String> etag() {
        return getAsString("ETag");
    }

    public Optional<String> location() {
        return getAsString("Location");
    }

    public Optional<String> proxyAuthenticate() {
        return getAsString("Proxy-Authenticate");
    }

    public Optional<String> retryAfter() {
        return getAsString("Retry-After");
    }

    public Optional<String> server() {
        return getAsString("Server");
    }

    public Optional<String> vary() {
        return getAsString("Vary");
    }

    public Optional<String> wwwAuthenticate() {
        return getAsString("WWW-Authenticate");
    }

    // --- Entity Headers ---
    public Optional<String> allow() {
        return getAsString("Allow");
    }

    public Optional<String> contentEncoding() {
        return getAsString("Content-Encoding");
    }

    public Optional<String> contentLanguage() {
        return getAsString("Content-Language");
    }

    public OptionalLong contentLength() {
        return getAsLong("Content-Length");
    }

    public Optional<String> contentLocation() {
        return getAsString("Content-Location");
    }

    public Optional<String> contentMD5() {
        return getAsString("Content-MD5");
    }

    public Optional<String> contentRange() {
        return getAsString("Content-Range");
    }

    public Optional<String> contentType() {
        return getAsString("Content-Type");
    }

    public Optional<String> expires() {
        return getAsString("Expires");
    }

    public Optional<String> lastModified() {
        return getAsString("Last-Modified");
    }

    public Optional<String> getAsString(String key) {
        var value = backing.get(key);
        if (value == null) {
            return Optional.empty();
        }
        
        if(value instanceof String val) {
            return Optional.of(val);
        }

        return Optional.of(Objects.toString(value));
    }

    public OptionalLong getAsLong(String key) {
        var value = backing.get(key);
        if (value == null) {
            return OptionalLong.empty();
        }
        
        if(value instanceof Number number) {
            return OptionalLong.of(number.longValue());
        }

        return OptionalLong.of(Long.parseLong(Objects.toString(value)));
    }

    public OptionalDouble getAsDouble(String key) {
        var value = backing.get(key);
        if (value == null) {
            return OptionalDouble.empty();
        }

        if(value instanceof Number number) {
            return OptionalDouble.of(number.doubleValue());
        }

        return OptionalDouble.of(Double.parseDouble(Objects.toString(value)));
    }

    public <T> Optional<T> getAs(String key, Function<Object, T> converter) {
        var value = backing.get(key);
        if (value == null) {
            return Optional.empty();
        }
        
        return Optional.of(converter.apply(value));
    }
}
