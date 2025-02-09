package it.auties.leap.http;

import it.auties.leap.http.async.client.AsyncHttpClientBuilder;
import it.auties.leap.http.blocking.client.BlockingHttpClientBuilder;

public sealed interface HttpClientBuilder permits AsyncHttpClientBuilder, BlockingHttpClientBuilder {
}
