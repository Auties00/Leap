package it.auties.leap.http.decoder;

import it.auties.leap.http.HttpResponse;

import java.net.URI;

public sealed interface HttpResult<T> {
    record Response<T>(int statusCode, boolean closeConnection, HttpResponse<T> data) implements HttpResult<T> {

    }

    record Redirect<T>(URI to) implements HttpResult<T> {

    }
}
