package it.auties.leap.http;

import it.auties.leap.http.async.AsyncHttpClientBuilder;
import it.auties.leap.http.blocking.BlockingHttpClientBuilder;

public sealed interface HttpClientBuilder permits AsyncHttpClientBuilder, BlockingHttpClientBuilder {
}
