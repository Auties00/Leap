package it.auties.leap.http.exchange.headers;

import java.util.*;
import java.util.function.BiConsumer;

// TODO: Parse known headers into builtin types(enums, dates,...)
public sealed class HttpHeaders permits HttpMutableHeaders {
    private static final HttpHeaders EMPTY = new HttpHeaders();
    protected final Map<String, List<String>> backing;

    HttpHeaders() {
        this.backing = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
    }

    HttpHeaders(Map<String, List<String>> backing) {
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

    public void forEach(BiConsumer<? super String, ? super List<String>> action) {
        backing.forEach(action);
    }

    public int size() {
        return backing.size();
    }

    public Optional<String> cacheControl() {
        return firstValue("Cache-Control");
    }

    public Optional<String> connection() {
        return firstValue("Connection");
    }

    public Optional<String> date() {
        return firstValue("Date");
    }

    public Optional<String> pragma() {
        return firstValue("Pragma");
    }

    public Optional<String> trailer() {
        return firstValue("Trailer");
    }

    public Optional<String> transferEncoding() {
        return firstValue("Transfer-Encoding");
    }

    public Optional<String> upgrade() {
        return firstValue("Upgrade");
    }

    public Optional<String> via() {
        return firstValue("Via");
    }

    public Optional<String> warning() {
        return firstValue("Warning");
    }
    
    public Optional<String> accept() {
        return firstValue("Accept");
    }

    public Optional<String> acceptCharset() {
        return firstValue("Accept-Charset");
    }

    public Optional<String> acceptEncoding() {
        return firstValue("Accept-Encoding");
    }

    public Optional<String> acceptLanguage() {
        return firstValue("Accept-Language");
    }

    public Optional<String> authorization() {
        return firstValue("Authorization");
    }

    public Optional<String> expect() {
        return firstValue("Expect");
    }

    public Optional<String> from() {
        return firstValue("From");
    }

    public Optional<String> host() {
        return firstValue("Host");
    }

    public Optional<String> ifMatch() {
        return firstValue("If-Match");
    }

    public Optional<String> ifModifiedSince() {
        return firstValue("If-Modified-Since");
    }

    public Optional<String> ifNoneMatch() {
        return firstValue("If-None-Match");
    }

    public Optional<String> ifRange() {
        return firstValue("If-Range");
    }

    public Optional<String> ifUnmodifiedSince() {
        return firstValue("If-Unmodified-Since");
    }

    public OptionalLong maxForwards() {
        return firstValueAsLong("Max-Forwards");
    }

    public Optional<String> proxyAuthorization() {
        return firstValue("Proxy-Authorization");
    }

    public Optional<String> range() {
        return firstValue("Range");
    }

    public Optional<String> referer() {
        return firstValue("Referer");
    }

    public Optional<String> te() {
        return firstValue("TE");
    }

    public Optional<String> userAgent() {
        return firstValue("User-Agent");
    }

    public Optional<String> acceptRanges() {
        return firstValue("Accept-Ranges");
    }

    public OptionalLong age() {
        return firstValueAsLong("Age");
    }

    public Optional<String> etag() {
        return firstValue("ETag");
    }

    public Optional<String> location() {
        return firstValue("Location");
    }

    public Optional<String> proxyAuthenticate() {
        return firstValue("Proxy-Authenticate");
    }

    public Optional<String> retryAfter() {
        return firstValue("Retry-After");
    }

    public Optional<String> server() {
        return firstValue("Server");
    }

    public Optional<String> vary() {
        return firstValue("Vary");
    }

    public Optional<String> wwwAuthenticate() {
        return firstValue("WWW-Authenticate");
    }

    public Optional<String> allow() {
        return firstValue("Allow");
    }

    public Optional<String> contentEncoding() {
        return firstValue("Content-Encoding");
    }

    public Optional<String> contentLanguage() {
        return firstValue("Content-Language");
    }

    public OptionalLong contentLength() {
        return firstValueAsLong("Content-Length");
    }

    public Optional<String> contentLocation() {
        return firstValue("Content-Location");
    }

    public Optional<String> contentMD5() {
        return firstValue("Content-MD5");
    }

    public Optional<String> contentRange() {
        return firstValue("Content-Range");
    }

    public Optional<String> contentType() {
        return firstValue("Content-Type");
    }

    public Optional<String> expires() {
        return firstValue("Expires");
    }

    public Optional<String> lastModified() {
        return firstValue("Last-Modified");
    }

    public Optional<String> firstValue(String key) {
        var value = backing.get(key);
        if(value == null || value.isEmpty()) {
            return Optional.empty();
        }

        return Optional.ofNullable(value.getFirst());
    }

    public OptionalLong firstValueAsLong(String key) {
        var values = backing.get(key);
        if(values == null || values.isEmpty()) {
            return OptionalLong.empty();
        }

        var value = values.getFirst();
        if(value == null) {
            return OptionalLong.empty();
        }

        try {
            return OptionalLong.of(Long.parseLong(value));
        }catch (NumberFormatException exception) {
            return OptionalLong.empty();
        }
    }

    public List<String> allValues(String key) {
        var values = backing.get(key);
        if(values == null) {
            return List.of();
        }

        return Collections.unmodifiableList(values);
    }
}
