package it.auties.leap.http;

import java.net.URI;
import java.util.Objects;
import java.util.Optional;

@SuppressWarnings("unused")
public sealed interface HttpResponse<T> {
    int statusCode();
    Optional<T> body();

    final class Result<T> implements HttpResponse<T> {
        private final int statusCode;
        private final T body;

        public Result(int statusCode, T body) {
            this.statusCode = statusCode;
            this.body = body;
        }

        @Override
        public int statusCode() {
            return statusCode;
        }

        @Override
        public Optional<T> body() {
            return Optional.ofNullable(body);
        }

        @Override
        public boolean equals(Object obj) {
            return obj instanceof Result<?> that
                    && that.statusCode == statusCode
                    && Objects.equals(that.body, body);
        }

        @Override
        public int hashCode() {
            return Objects.hash(statusCode, body);
        }

        @Override
        public String toString() {
            return "HttpResponse[" +
                    "statusCode=" + statusCode + ", " +
                    "body=" + body + ']';
        }
    }

    record Redirect<T>(int statusCode, URI to) implements HttpResponse<T> {
        @Override
        public Optional<T> body() {
            return Optional.empty();
        }
    }
}
